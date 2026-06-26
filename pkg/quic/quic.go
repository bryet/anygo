package quic

// anygo UDP tunnel — fully aligned with TUIC v5 protocol
//
// data flow:
//   local UDP traffic
//     ↓ plain UDP packet
//   inbound (acts as TUIC v5 client)
//     ↓ standard TUIC v5 protocol (QUIC + anygo-quic ALPN)
//   outbound (acts as TUIC v5 server)
//     ↓ plain UDP packet
//   target UDP node
//
// TUIC v5 protocol spec: https://github.com/tuic-protocol/tuic/blob/master/SPEC.md

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/logger"
	"anygo/pkg/util"

	quicgo "github.com/quic-go/quic-go"
)

// ─────────────────────────────────────────────────────────────────────────────
// TUIC v5 protocol constants
// ─────────────────────────────────────────────────────────────────────────────

// udpBufPool reuses large UDP read buffers to reduce GC pressure.
// Get/Put pattern: buf := udpBufPool.Get().([]byte); defer udpBufPool.Put(buf[:udpBufSize])
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufSize)
		return b
	},
}

const (
	tuicVersion = 0x05

	// command types
	cmdAuthenticate = 0x00
	cmdConnect      = 0x01
	cmdPacket       = 0x02
	cmdDissociate   = 0x03
	cmdHeartbeat    = 0x04

	// address types
	addrNone   = 0xff
	addrDomain = 0x00
	addrIPv4   = 0x01
	addrIPv6   = 0x02

	// QUIC ALPN — compatible with standard TUIC v5 implementations (e.g. sing-box).
	// Change to a custom value if you want to isolate anygo from other TUIC nodes.
	quicALPN = "tuic-v5"

	// timeouts
	dialTimeout    = 10 * time.Second
	idleTimeout    = 120 * time.Second
	sessionIdle    = 60 * time.Second
	heartbeatEvery = 10 * time.Second

	udpBufSize = 65535

	// max QUIC datagram payload (conservative; reserves space for TUIC header + QUIC frame overhead)
	// UDP packets larger than this are automatically fragmented and reassembled on the receive side
	maxDatagramPayload = 1100

	// maxInboundSessions is the hard cap on the number of inSession entries per Inbound.
	// Each entry represents a unique client (source IP:port → assocID mapping).
	// Without a cap, a flood of spoofed source addresses can grow the sessions map
	// unboundedly; Go maps never shrink their backing array, so even idle cleanup
	// cannot reclaim hash-table memory after a spike. Override by setting MAX_TUIC_SESSIONS
	// in the environment, or 0 to disable (not recommended for production).
	defaultMaxInboundSessions = 50000

	// maxOutboundSessionsPerConn is the hard cap on outSession entries per QUIC
	// connection on the outbound side. Each entry holds a UDP socket (fd + kernel
	// buffers). 0 disables.
	defaultMaxOutboundSessionsPerConn = 10000
)

// ─────────────────────────────────────────────────────────────────────────────
// TUIC v5 address codec
// ─────────────────────────────────────────────────────────────────────────────

type tuicAddr struct {
	typ  byte
	host string
	port uint16
}

func readAddr(r io.Reader) (tuicAddr, error) {
	typ := make([]byte, 1)
	if _, err := io.ReadFull(r, typ); err != nil {
		return tuicAddr{}, err
	}
	a := tuicAddr{typ: typ[0]}
	switch a.typ {
	case addrIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return tuicAddr{}, err
		}
		a.host = net.IP(buf[:4]).String()
		a.port = binary.BigEndian.Uint16(buf[4:])
	case addrIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return tuicAddr{}, err
		}
		a.host = net.IP(buf[:16]).String()
		a.port = binary.BigEndian.Uint16(buf[16:])
	case addrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return tuicAddr{}, err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return tuicAddr{}, err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return tuicAddr{}, err
		}
		a.host = string(domain)
		a.port = binary.BigEndian.Uint16(portBuf)
	case addrNone:
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return tuicAddr{}, err
		}
		a.port = binary.BigEndian.Uint16(portBuf)
	default:
		return tuicAddr{}, fmt.Errorf("unknown address type: 0x%02x", a.typ)
	}
	return a, nil
}

func writeAddr(w io.Writer, a tuicAddr) error {
	switch a.typ {
	case addrIPv4:
		ip := net.ParseIP(a.host).To4()
		buf := make([]byte, 1+4+2)
		buf[0] = addrIPv4
		copy(buf[1:], ip)
		binary.BigEndian.PutUint16(buf[5:], a.port)
		_, err := w.Write(buf)
		return err
	case addrIPv6:
		ip := net.ParseIP(a.host).To16()
		buf := make([]byte, 1+16+2)
		buf[0] = addrIPv6
		copy(buf[1:], ip)
		binary.BigEndian.PutUint16(buf[17:], a.port)
		_, err := w.Write(buf)
		return err
	case addrDomain:
		d := []byte(a.host)
		buf := make([]byte, 1+1+len(d)+2)
		buf[0] = addrDomain
		buf[1] = byte(len(d))
		copy(buf[2:], d)
		binary.BigEndian.PutUint16(buf[2+len(d):], a.port)
		_, err := w.Write(buf)
		return err
	case addrNone:
		buf := make([]byte, 1+2)
		buf[0] = addrNone
		binary.BigEndian.PutUint16(buf[1:], a.port)
		_, err := w.Write(buf)
		return err
	}
	return fmt.Errorf("unknown address type: 0x%02x", a.typ)
}

func udpAddrToTUIC(a *net.UDPAddr) tuicAddr {
	if ip4 := a.IP.To4(); ip4 != nil {
		return tuicAddr{typ: addrIPv4, host: ip4.String(), port: uint16(a.Port)}
	}
	return tuicAddr{typ: addrIPv6, host: a.IP.String(), port: uint16(a.Port)}
}

// ─────────────────────────────────────────────────────────────────────────────
// TUIC v5 Packet command
//
// frame format (unidirectional stream):
//   client→server：| VER(1) | TYPE(1) | ASSOC_ID(2) | PKT_ID(2) |
//                  | FRAG_TOTAL(1) | FRAG_ID(1) | SIZE(2) | ADDR | DATA |
//   server→client：same as above; ADDR is the source address
// ─────────────────────────────────────────────────────────────────────────────

type tuicPacket struct {
	assocID   uint16
	pktID     uint16
	fragTotal uint8
	fragID    uint8
	size      uint16
	addr      tuicAddr
	data      []byte
}

// readPacket reads a complete Packet command from a unidirectional stream
// VER+TYPE header bytes must be read before calling
func readPacket(r io.Reader) (tuicPacket, error) {
	hdr := make([]byte, 2+2+1+1+2) // assocID+pktID+fragTotal+fragID+size
	if _, err := io.ReadFull(r, hdr); err != nil {
		return tuicPacket{}, err
	}
	pkt := tuicPacket{
		assocID:   binary.BigEndian.Uint16(hdr[0:2]),
		pktID:     binary.BigEndian.Uint16(hdr[2:4]),
		fragTotal: hdr[4],
		fragID:    hdr[5],
		size:      binary.BigEndian.Uint16(hdr[6:8]),
	}
	addr, err := readAddr(r)
	if err != nil {
		return tuicPacket{}, err
	}
	pkt.addr = addr
	pkt.data = make([]byte, pkt.size)
	if _, err := io.ReadFull(r, pkt.data); err != nil {
		return tuicPacket{}, err
	}
	return pkt, nil
}

// writePacket writes a complete Packet command frame (including VER+TYPE header)
func writePacket(w io.Writer, pkt tuicPacket) error {
	hdr := make([]byte, 1+1+2+2+1+1+2)
	hdr[0] = tuicVersion
	hdr[1] = cmdPacket
	binary.BigEndian.PutUint16(hdr[2:4], pkt.assocID)
	binary.BigEndian.PutUint16(hdr[4:6], pkt.pktID)
	hdr[6] = pkt.fragTotal
	hdr[7] = pkt.fragID
	binary.BigEndian.PutUint16(hdr[8:10], pkt.size)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if err := writeAddr(w, pkt.addr); err != nil {
		return err
	}
	_, err := w.Write(pkt.data)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// fragmentation & reassembly (TUIC v5 native mode) (TUIC v5 native mode)
// ─────────────────────────────────────────────────────────────────────────────

// fragKey is the index key for fragment reassembly buffers
type fragKey struct {
	assocID uint16
	pktID   uint16
}

// fragBuf is a fragment reassembly buffer
type fragBuf struct {
	total    uint8
	received uint8
	frags    map[uint8][]byte
	deadline time.Time
}

// sendDatagramPkt sends a Packet command
// if data exceeds maxDatagramPayload, auto-fragment and send each piece as a separate datagram
func sendDatagramPkt(qconn *quicgo.Conn, pkt tuicPacket) error {
	if len(pkt.data) <= maxDatagramPayload {
		dgram, err := writePacketBytes(pkt)
		if err != nil {
			return err
		}
		return qconn.SendDatagram(dgram)
	}

	data := pkt.data
	total := (len(data) + maxDatagramPayload - 1) / maxDatagramPayload
	if total > 255 {
		total = 255
	}
	for i := 0; i < total; i++ {
		start := i * maxDatagramPayload
		end := start + maxDatagramPayload
		if end > len(data) {
			end = len(data)
		}
		addr := tuicAddr{typ: addrNone, port: 0}
		if i == 0 {
			addr = pkt.addr // the first fragment carries the original address
		}
		frag := tuicPacket{
			assocID:   pkt.assocID,
			pktID:     pkt.pktID,
			fragTotal: uint8(total),
			fragID:    uint8(i),
			size:      uint16(end - start),
			addr:      addr,
			data:      data[start:end],
		}
		dgram, err := writePacketBytes(frag)
		if err != nil {
			return err
		}
		if err := qconn.SendDatagram(dgram); err != nil {
			return err
		}
	}
	return nil
}

// reassemblePkt adds a received pkt to the fragment buffer; returns the reassembled data when all fragments arrive
// frags is managed by the caller (single goroutine), no locking needed
// returns (data, true) when reassembly is complete; (nil, false) when waiting for more fragments
func reassemblePkt(frags map[fragKey]*fragBuf, pkt tuicPacket) ([]byte, bool) {
	if pkt.fragTotal == 1 {
		// no fragmentation, return directly (copy to prevent underlying slice reuse)
		data := make([]byte, len(pkt.data))
		copy(data, pkt.data)
		return data, true
	}

	key := fragKey{assocID: pkt.assocID, pktID: pkt.pktID}
	fb, ok := frags[key]
	if !ok {
		fb = &fragBuf{
			total:    pkt.fragTotal,
			frags:    make(map[uint8][]byte),
			deadline: time.Now().Add(10 * time.Second),
		}
		frags[key] = fb
	}
	// store fragment (copy to prevent underlying data reuse)
	buf := make([]byte, len(pkt.data))
	copy(buf, pkt.data)
	fb.frags[pkt.fragID] = buf
	fb.received++

	if fb.received < fb.total {
		return nil, false
	}

	// all fragments arrived; concatenate in fragID order
	var full []byte
	for i := uint8(0); i < fb.total; i++ {
		full = append(full, fb.frags[i]...)
	}
	delete(frags, key)
	return full, true
}

// writePacketBytes serializes a Packet command to []byte for QUIC datagram sending
func writePacketBytes(pkt tuicPacket) ([]byte, error) {
	// estimate address length
	var addrLen int
	switch pkt.addr.typ {
	case addrIPv4:
		addrLen = 1 + 4 + 2
	case addrIPv6:
		addrLen = 1 + 16 + 2
	case addrDomain:
		addrLen = 1 + 1 + len(pkt.addr.host) + 2
	case addrNone:
		addrLen = 1 + 2
	default:
		addrLen = 1 + 2
	}
	w := bytes.NewBuffer(make([]byte, 0, 1+1+2+2+1+1+2+addrLen+len(pkt.data)))
	if err := writePacket(w, pkt); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// readPacketFromBytes parses a Packet command from []byte (skipping the 2-byte VER+TYPE header)
func readPacketFromBytes(data []byte) (tuicPacket, error) {
	if len(data) < 2 {
		return tuicPacket{}, fmt.Errorf("datagram too short")
	}
	r := bytes.NewReader(data[2:]) // skip VER+TYPE
	return readPacket(r)
}

// cleanupFrags removes timed-out fragment buffers from the map.
// Called both on datagram arrival and during periodic timeout to prevent memory leaks.
func cleanupFrags(frags map[fragKey]*fragBuf) {
	now := time.Now()
	for k, fb := range frags {
		if now.After(fb.deadline) {
			delete(frags, k)
		}
	}
}

// receiveStreamReader adapts *quicgo.ReceiveStream to io.Reader
type receiveStreamReader struct{ s *quicgo.ReceiveStream }

func (r *receiveStreamReader) Read(p []byte) (int, error) { return (*r.s).Read(p) }

// ─────────────────────────────────────────────────────────────────────────────
// Inbound: acts as TUIC v5 client
//
// TUIC v5 client responsibilities:
//   1. establish QUIC connection
//   2. send Authenticate command via unidirectional stream
//   3. when receiving a local UDP packet, send a Packet command via unidirectional stream
//      - assocID: assigned per local client address; same address reuses the same assocID
//      - pktID: monotonically increasing per packet
//      - fragTotal=1, fragID=0 (no fragmentation)
//      - addr: target address (always the outbound remote in anygo)
//   4. accept unidirectional streams from outbound, parse Packet commands,
//      and write back to the corresponding local client
//   5. periodically send Heartbeat via QUIC datagram when there are active sessions
//   6. session becomes idle, send Dissociate command via unidirectional stream
// ─────────────────────────────────────────────────────────────────────────────

type inSession struct {
	assocID    uint16
	clientAddr *net.UDPAddr
	nextPktID  uint16
	lastActive time.Time
	mu         sync.Mutex
}

func (s *inSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *inSession) idle() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActive)
}

func (s *inSession) allocPktID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextPktID
	s.nextPktID++
	return id
}

type dialCall struct {
	wg  sync.WaitGroup
	val *quicgo.Conn
	err error
}

type inboundStats struct {
	totalPkts atomic.Int64
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
}

type Inbound struct {
	cfg       *config.MergedConfig
	localConn *net.UDPConn

	conn   *quicgo.Conn
	connMu sync.RWMutex

	dialMu  sync.Mutex
	dialing *dialCall

	sessions    map[string]*inSession // clientAddr → session
	sessionsMu  sync.Mutex
	nextAssoc   uint16
	maxSessions int // hard cap on sessions map size; 0 = use default

	stats inboundStats
	sem   chan struct{}
}

func NewInbound(cfg *config.MergedConfig) *Inbound {
	ib := &Inbound{
		cfg:         cfg,
		sessions:    make(map[string]*inSession),
		maxSessions: defaultMaxInboundSessions,
	}
	if v := os.Getenv("MAX_TUIC_SESSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ib.maxSessions = n
		}
	}
	if cfg.MaxConns > 0 {
		ib.sem = make(chan struct{}, cfg.MaxConns)
	}
	return ib
}

func (ib *Inbound) Run() error {
	addr, err := net.ResolveUDPAddr("udp", ib.cfg.Listen)
	if err != nil {
		return err
	}
	lconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer lconn.Close()
	ib.localConn = lconn

	logger.Info("[tuic-inbound] listening %s (TUIC client) → %s", ib.cfg.Listen, ib.cfg.Remote)

	go ib.statsLoop()
	go ib.cleanupLoop()

	buf := make([]byte, udpBufSize)
	for {
		n, clientAddr, err := lconn.ReadFromUDP(buf)
		if err != nil {
			logger.Error("[tuic-inbound] read error: %v", err)
			continue
		}
		if ib.sem != nil {
			select {
			case ib.sem <- struct{}{}:
			default:
				logger.Warn("[tuic-inbound] packet concurrency limit reached, dropping")
				continue
			}
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go ib.handleUDP(clientAddr, data)
	}
}

func (ib *Inbound) getOrCreateSession(clientAddr *net.UDPAddr) *inSession {
	key := clientAddr.String()
	ib.sessionsMu.Lock()
	defer ib.sessionsMu.Unlock()
	if s, ok := ib.sessions[key]; ok {
		return s
	}
	// Hard cap: prevent sessions map from growing unboundedly.
	// Go maps never shrink their backing array, so even after idle cleanup
	// the hash-table memory from a spike is retained indefinitely.
	if ib.maxSessions > 0 && len(ib.sessions) >= ib.maxSessions {
		logger.Warn("[tuic-inbound] sessions cap reached (%d), rejecting new client %s",
			ib.maxSessions, key)
		return nil
	}
	ib.nextAssoc++
	s := &inSession{
		assocID:    ib.nextAssoc,
		clientAddr: clientAddr,
		lastActive: time.Now(),
	}
	ib.sessions[key] = s
	logger.Debug("[tuic-inbound] new session assocID=%d client=%s", s.assocID, key)
	return s
}

func (ib *Inbound) handleUDP(clientAddr *net.UDPAddr, data []byte) {
	defer func() {
		if ib.sem != nil {
			<-ib.sem
		}
	}()

	ib.stats.totalPkts.Add(1)
	ib.stats.bytesIn.Add(int64(len(data)))

	qconn, err := ib.getConn()
	if err != nil {
		logger.Error("[tuic-inbound] failed to get QUIC connection: %v", err)
		return
	}

	sess := ib.getOrCreateSession(clientAddr)
	if sess == nil {
		// Session cap reached; packet dropped (already logged in getOrCreateSession).
		return
	}
	sess.touch()

	// build Packet command
	pkt := tuicPacket{
		assocID:   sess.assocID,
		pktID:     sess.allocPktID(),
		fragTotal: 1,
		fragID:    0,
		size:      uint16(len(data)),
		addr:      tuicAddr{typ: addrNone, port: 0},
		data:      data,
	}

	// send via QUIC datagram (auto-fragment if exceeding maxDatagramPayload)
	if err := sendDatagramPkt(qconn, pkt); err != nil {
		select {
		case <-qconn.Context().Done():
			ib.connMu.Lock()
			ib.conn = nil
			ib.connMu.Unlock()
		default:
		}
		logger.Debug("[tuic-inbound] failed to send datagram: %v", err)
		return
	}
	logger.Debug("[tuic-inbound] → Packet(dgram) assocID=%d pktID=%d size=%d",
		pkt.assocID, pkt.pktID, pkt.size)
}

// getConn gets or rebuilds the QUIC connection (singleflight)
func (ib *Inbound) getConn() (*quicgo.Conn, error) {
	ib.connMu.RLock()
	conn := ib.conn
	ib.connMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
		default:
			return conn, nil
		}
	}

	ib.dialMu.Lock()
	if ib.dialing != nil {
		call := ib.dialing
		ib.dialMu.Unlock()
		call.wg.Wait()
		return call.val, call.err
	}
	call := &dialCall{}
	call.wg.Add(1)
	ib.dialing = call
	ib.dialMu.Unlock()

	call.val, call.err = ib.dial()
	call.wg.Done()

	ib.dialMu.Lock()
	ib.dialing = nil
	ib.dialMu.Unlock()

	return call.val, call.err
}

func (ib *Inbound) dial() (*quicgo.Conn, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: ib.cfg.Insecure,
		ServerName:         ib.cfg.SNI,
		NextProtos:         []string{quicALPN},
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	qconn, err := quicgo.DialAddr(ctx, ib.cfg.Remote, tlsCfg, &quicgo.Config{
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingUniStreams:           65535,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
	})
	if err != nil {
		return nil, err
	}

	// ── TUIC v5 Authenticate ──────────────────────────────────────────────────
	// send via unidirectional stream: | VER(1) | TYPE(1) | UUID(16) | TOKEN(32) |
	// TOKEN = sha256(password) (simplified auth; both anygo ends are self-controlled)
	authCtx, authCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer authCancel()

	authStream, err := qconn.OpenUniStreamSync(authCtx)
	if err != nil {
		qconn.CloseWithError(0, "auth failed")
		return nil, err
	}
	h := sha256.Sum256([]byte(ib.cfg.Password))
	// UUID: first 16 bytes of password hash (anygo internal convention, no real UUID needed)
	authBuf := make([]byte, 1+1+16+32)
	authBuf[0] = tuicVersion
	authBuf[1] = cmdAuthenticate
	copy(authBuf[2:18], h[:16])  // UUID
	copy(authBuf[18:50], h[:])   // TOKEN
	if _, err := authStream.Write(authBuf); err != nil {
		qconn.CloseWithError(0, "auth failed")
		return nil, err
	}
	authStream.Close()
	// ─────────────────────────────────────────────────────────────────────────

	ib.connMu.Lock()
	ib.conn = qconn
	ib.connMu.Unlock()

	// clean up old sessions (old assocIDs become invalid after reconnection)
	ib.sessionsMu.Lock()
	ib.sessions = make(map[string]*inSession)
	ib.sessionsMu.Unlock()

	// start receive loop: accept Packet commands from outbound
	go ib.recvLoop(qconn)
	// start heartbeat
	go ib.heartbeatLoop(qconn)

	logger.Info("[tuic-inbound] QUIC connection established → %s", ib.cfg.Remote)
	return qconn, nil
}

const fragCleanupInterval = 10 * time.Second

// recvLoop receives Packet commands pushed back from outbound via datagrams
// supports fragment reassembly: when fragTotal>1, wait for all fragments before writing back to local
func (ib *Inbound) recvLoop(qconn *quicgo.Conn) {
	frags := make(map[fragKey]*fragBuf) // fragment reassembly buffer (single goroutine access, no locking needed)
	for {
		// Use a timeout so we periodically clean up timed-out fragments
		// even when no new datagrams arrive (prevents memory leak).
		ctx, cancel := context.WithTimeout(context.Background(), fragCleanupInterval)
		dgram, err := qconn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// Timeout is expected — clean up and continue.
				cleanupFrags(frags)
				continue
			}
			return // real error, connection closed
		}
		if len(dgram) < 2 || dgram[0] != tuicVersion || dgram[1] != cmdPacket {
			continue
		}
		pkt, err := readPacketFromBytes(dgram)
		if err != nil {
			continue
		}

		// clean up timed-out fragments (also done during timeout above)
		cleanupFrags(frags)

		// fragment reassembly
		data, ok := reassemblePkt(frags, pkt)
		if !ok {
			continue // waiting for more fragments
		}

		ib.sessionsMu.Lock()
		var target *inSession
		for _, s := range ib.sessions {
			if s.assocID == pkt.assocID {
				target = s
				break
			}
		}
		ib.sessionsMu.Unlock()

		if target == nil {
			logger.Warn("[tuic-inbound] response for UNKNOWN assocID=%d, ignoring", pkt.assocID)
			continue
		}

		target.touch()
		ib.stats.bytesOut.Add(int64(len(data)))
		n, err := ib.localConn.WriteToUDP(data, target.clientAddr)
		if err != nil {
			logger.Warn("[tuic-inbound] WriteToUDP error assocID=%d addr=%s: %v", pkt.assocID, target.clientAddr, err)
		}
		logger.Debug("[tuic-inbound] <- Packet(dgram) assocID=%d pktID=%d size=%d -> %s written=%d",
			pkt.assocID, pkt.pktID, len(data), target.clientAddr, n)
	}
}

// heartbeatLoop periodically sends TUIC v5 Heartbeat datagrams when there are active sessions
// | VER(1) | TYPE(1) |
func (ib *Inbound) heartbeatLoop(qconn *quicgo.Conn) {
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-qconn.Context().Done():
			return
		case <-ticker.C:
			ib.sessionsMu.Lock()
			hasSess := len(ib.sessions) > 0
			ib.sessionsMu.Unlock()
			if !hasSess {
				continue
			}
			hb := []byte{tuicVersion, cmdHeartbeat}
			if err := qconn.SendDatagram(hb); err != nil {
				return
			}
		}
	}
}

// cleanupLoop periodically cleans up idle sessions and sends TUIC v5 Dissociate commands.
// Also compacts the sessions map when it becomes empty to prevent Go map backing-array
// retention after traffic spikes.
func (ib *Inbound) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	compactTick := 0
	const compactEvery = 20 // compact every 20 × 15s = 5 minutes

	for range ticker.C {
		now := time.Now()
		ib.sessionsMu.Lock()
		var toRemove []*inSession
		for key, s := range ib.sessions {
			if now.Sub(s.lastActive) > sessionIdle {
				toRemove = append(toRemove, s)
				delete(ib.sessions, key)
			}
		}

		// Compact the map periodically: if empty, replace to release peak capacity.
		// Go maps don't shrink; a spike of 10k clients would retain ~1MB+ of hash table
		// indefinitely without this.
		compactTick++
		if compactTick >= compactEvery && len(ib.sessions) == 0 {
			ib.sessions = make(map[string]*inSession)
			compactTick = 0
		}
		ib.sessionsMu.Unlock()

		for _, s := range toRemove {
			logger.Debug("[tuic-inbound] session timed out assocID=%d, sending Dissociate", s.assocID)
			go ib.sendDissociate(s.assocID)
		}
	}
}

// sendDissociate sends a TUIC v5 Dissociate command via unidirectional stream
// | VER(1) | TYPE(1) | ASSOC_ID(2) |
func (ib *Inbound) sendDissociate(assocID uint16) {
	qconn, err := ib.getConn()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := qconn.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	buf := make([]byte, 1+1+2)
	buf[0] = tuicVersion
	buf[1] = cmdDissociate
	binary.BigEndian.PutUint16(buf[2:], assocID)
	stream.Write(buf)
	stream.Close()
}

func (ib *Inbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[tuic-inbound:%s] stats | total packets: %d  rx: %s  tx: %s",
			ib.cfg.Listen,
			ib.stats.totalPkts.Load(),
			util.FormatBytes(ib.stats.bytesIn.Load()),
			util.FormatBytes(ib.stats.bytesOut.Load()),
		)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Outbound: acts as TUIC v5 server
//
// TUIC v5 server responsibilities:
//   1. listen for QUIC connections
//   2. accept unidirectional streams, parse commands:
//      - Authenticate: verify TOKEN, mark connection as authenticated
//      - Packet: lookup or create UDP socket by assocID, forward to target address
//      - Dissociate: close the corresponding UDP socket
//   3. when receiving a UDP response from target, send a Packet command back via unidirectional stream
//      (source address is the actual address the response came from)
//   4. accept QUIC datagrams; ignore Heartbeat (keepalive is handled at the QUIC layer)
// ─────────────────────────────────────────────────────────────────────────────

type outSession struct {
	assocID    uint16
	udpConn    *net.UDPConn
	lastActive time.Time
	mu         sync.Mutex
	closed     bool
}

func (s *outSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *outSession) idle() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActive)
}

func (s *outSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.udpConn.Close()
	}
}

type outboundStats struct {
	totalConns  atomic.Int64
	activeConns atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

type Outbound struct {
	cfg        *config.MergedConfig
	targetAddr *net.UDPAddr
	stats      outboundStats
	sem        chan struct{}
}

func NewOutbound(cfg *config.MergedConfig) *Outbound {
	ob := &Outbound{cfg: cfg}
	if cfg.MaxConns > 0 {
		ob.sem = make(chan struct{}, cfg.MaxConns)
	}
	return ob
}

func (ob *Outbound) Run() error {
	targetAddr, err := net.ResolveUDPAddr("udp", ob.cfg.Remote)
	if err != nil {
		return fmt.Errorf("failed to resolve target address: %w", err)
	}
	ob.targetAddr = targetAddr

	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}

	listener, err := quicgo.ListenAddr(ob.cfg.Listen, tlsCfg, &quicgo.Config{
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingUniStreams:           65535,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Info("[tuic-outbound] listening %s (TUIC server) → %s", ob.cfg.Listen, ob.cfg.Remote)
	go ob.statsLoop()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logger.Error("[tuic-outbound] accept error: %v", err)
			continue
		}
		if ob.sem != nil {
			select {
			case ob.sem <- struct{}{}:
			default:
				logger.Warn("[tuic-outbound] connection limit reached, rejecting")
				conn.CloseWithError(0, "too many connections")
				continue
			}
		}
		ob.stats.totalConns.Add(1)
		ob.stats.activeConns.Add(1)
		go ob.handleConn(conn)
	}
}

// connState holds per-QUIC-connection state
type connState struct {
	ob          *Outbound
	qconn       *quicgo.Conn
	authed      atomic.Bool
	sessions    map[uint16]*outSession
	sessionsMu  sync.Mutex
	maxSessions int // hard cap on outSession entries (0 = use default)
	// pending command buffer (commands arriving before auth are buffered)
	pendingMu sync.Mutex
	pending   []func()
}

func (ob *Outbound) handleConn(qconn *quicgo.Conn) {
	defer func() {
		qconn.CloseWithError(0, "done")
		ob.stats.activeConns.Add(-1)
		if ob.sem != nil {
			<-ob.sem
		}
	}()

	maxOutSess := defaultMaxOutboundSessionsPerConn
	if v := os.Getenv("MAX_TUIC_OUTBOUND_SESSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxOutSess = n
		}
	}
	cs := &connState{
		ob:          ob,
		qconn:       qconn,
		sessions:    make(map[uint16]*outSession),
		maxSessions: maxOutSess,
	}

	// Per TUIC v5 spec, the first unidirectional stream MUST be Authenticate.
	// We must process it BEFORE starting recvDatagrams, otherwise a Packet
	// datagram that arrives before the AUTH stream is processed gets silently
	// dropped (authed==false). This is the root cause of "first packet lost"
	// and makes UDP tunnels appear non-functional with single-packet tests.
	if err := cs.waitAuth(); err != nil {
		qconn.CloseWithError(1, "auth timeout")
		return
	}

	// Now safe to receive datagrams and remaining streams.
	go cs.recvDatagrams()
	go cs.sessionCleanup()

	// loop accepting remaining unidirectional streams
	for {
		stream, err := qconn.AcceptUniStream(context.Background())
		if err != nil {
			break
		}
		go cs.handleStream(stream)
	}

	// close all sessions
	cs.sessionsMu.Lock()
	for _, s := range cs.sessions {
		s.close()
	}
	cs.sessionsMu.Unlock()
}

// waitAuth waits for and processes the first unidirectional stream, which per
// TUIC v5 spec MUST be an Authenticate command. Must complete before starting
// recvDatagrams to prevent dropping early Packet datagrams.
func (cs *connState) waitAuth() error {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	stream, err := cs.qconn.AcceptUniStream(ctx)
	if err != nil {
		return err
	}
	return cs.handleAuthStream(stream)
}

// handleAuthStream reads and processes an Authenticate command from a stream.
func (cs *connState) handleAuthStream(stream *quicgo.ReceiveStream) error {
	r := &receiveStreamReader{s: stream}
	defer (*stream).CancelRead(0)
	(*stream).SetReadDeadline(time.Now().Add(dialTimeout))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("auth: failed to read header: %w", err)
	}
	if hdr[0] != tuicVersion {
		return fmt.Errorf("auth: unknown TUIC version 0x%02x", hdr[0])
	}
	if hdr[1] != cmdAuthenticate {
		return fmt.Errorf("auth: expected cmdAuthenticate(0x00), got 0x%02x", hdr[1])
	}
	cs.handleAuth(r)
	if !cs.authed.Load() {
		return fmt.Errorf("auth: authentication rejected")
	}
	return nil
}

// recvDatagrams handles all inbound datagrams: Heartbeat and Packet commands
// supports fragment reassembly; processes inline in the loop to reduce goroutine overhead
func (cs *connState) recvDatagrams() {
	frags := make(map[fragKey]*fragBuf) // fragment reassembly buffer (single goroutine access, no locking needed)
	for {
		// Use a timeout so we periodically clean up timed-out fragments
		// even when no new datagrams arrive (prevents memory leak).
		ctx, cancel := context.WithTimeout(context.Background(), fragCleanupInterval)
		dgram, err := cs.qconn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				cleanupFrags(frags)
				continue
			}
			return
		}
		if len(dgram) < 2 || dgram[0] != tuicVersion {
			continue
		}
		switch dgram[1] {
		case cmdHeartbeat:
			logger.Debug("[tuic-outbound] received Heartbeat")
		case cmdPacket:
			if !cs.authed.Load() {
				logger.Warn("[tuic-outbound] unauthenticated connection sent Packet(dgram), ignoring")
				continue
			}
			pkt, err := readPacketFromBytes(dgram)
			if err != nil {
				continue
			}

			// clean up timed-out fragments (also done during timeout above)
			cleanupFrags(frags)

			// fragment reassembly
			data, ok := reassemblePkt(frags, pkt)
			if !ok {
				continue // waiting for more fragments
			}

			cs.ob.stats.bytesIn.Add(int64(len(data)))
			logger.Debug("[tuic-outbound] ← Packet(dgram) assocID=%d pktID=%d size=%d",
				pkt.assocID, pkt.pktID, len(data))

			cs.sessionsMu.Lock()
			sess, ok2 := cs.sessions[pkt.assocID]
			if !ok2 {
				// Hard cap: prevent per-connection sessions from growing
				// unboundedly (each holds a UDP socket fd + kernel buffers).
				if cs.maxSessions > 0 && len(cs.sessions) >= cs.maxSessions {
					cs.sessionsMu.Unlock()
					logger.Warn("[tuic-outbound] per-conn sessions cap reached (%d), dropping assocID=%d",
						cs.maxSessions, pkt.assocID)
					continue
				}
				udpConn, err := net.DialUDP("udp", nil, cs.ob.targetAddr)
				if err != nil {
					cs.sessionsMu.Unlock()
					logger.Error("[tuic-outbound] failed to create UDP socket assocID=%d: %v", pkt.assocID, err)
					continue
				}
				sess = &outSession{
					assocID:    pkt.assocID,
					udpConn:    udpConn,
					lastActive: time.Now(),
				}
				cs.sessions[pkt.assocID] = sess
				logger.Debug("[tuic-outbound] new session assocID=%d → %s", pkt.assocID, cs.ob.targetAddr)
				go cs.recvFromTarget(pkt.assocID, sess)
			}
			cs.sessionsMu.Unlock()

			sess.touch()
			if _, err := sess.udpConn.Write(data); err != nil {
				logger.Debug("[tuic-outbound] UDP send failed assocID=%d: %v", pkt.assocID, err)
			}
		}
	}
}

func (cs *connState) sessionCleanup() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cs.qconn.Context().Done():
			return
		case <-ticker.C:
			cs.sessionsMu.Lock()
			for id, s := range cs.sessions {
				if s.idle() > sessionIdle {
					logger.Debug("[tuic-outbound] session timed out assocID=%d", id)
					s.close()
					delete(cs.sessions, id)
				}
			}
			cs.sessionsMu.Unlock()
		}
	}
}

func (cs *connState) handleStream(stream *quicgo.ReceiveStream) {
	r := &receiveStreamReader{s: stream}
	defer (*stream).CancelRead(0)
	(*stream).SetReadDeadline(time.Now().Add(idleTimeout))

	// read VER + TYPE
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != tuicVersion {
		logger.Warn("[tuic-outbound] unknown TUIC version: 0x%02x", hdr[0])
		return
	}

	switch hdr[1] {
	case cmdAuthenticate:
		cs.handleAuth(r)
	case cmdPacket:
		// Packet commands now use datagram transport, ignoring stream-based Packet
		logger.Debug("[tuic-outbound] received stream-based Packet, now using datagrams, ignoring")
	case cmdDissociate:
		if !cs.authed.Load() {
			return
		}
		cs.handleDissociate(r)
	}
}

// handleAuth processes the TUIC v5 Authenticate command
// | UUID(16) | TOKEN(32) |(VER+TYPE already read)
func (cs *connState) handleAuth(r io.Reader) {
	buf := make([]byte, 16+32)
	if _, err := io.ReadFull(r, buf); err != nil {
		cs.qconn.CloseWithError(1, "auth read failed")
		return
	}
	token := buf[16:] // TOKEN follows UUID
	expected := sha256.Sum256([]byte(cs.ob.cfg.Password))
	if !util.EqualBytes(token, expected[:]) {
		logger.Warn("[tuic-outbound] auth failed from %s", cs.qconn.RemoteAddr())
		cs.qconn.CloseWithError(1, "auth failed")
		return
	}
	cs.authed.Store(true)
	logger.Debug("[tuic-outbound] auth succeeded: %s", cs.qconn.RemoteAddr())
}

// handleDissociate processes the TUIC v5 Dissociate command
// | ASSOC_ID(2) |(VER+TYPE already read)
func (cs *connState) handleDissociate(r io.Reader) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return
	}
	assocID := binary.BigEndian.Uint16(buf)
	cs.sessionsMu.Lock()
	if s, ok := cs.sessions[assocID]; ok {
		s.close()
		delete(cs.sessions, assocID)
	}
	cs.sessionsMu.Unlock()
	logger.Debug("[tuic-outbound] Dissociate assocID=%d", assocID)
}

// recvFromTarget continuously receives responses from the target UDP node and sends them back to the client via unidirectional stream
// response Packet command: ADDR is filled with the actual source address (as required by TUIC v5 spec)
func (cs *connState) recvFromTarget(assocID uint16, sess *outSession) {
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf) //nolint:staticcheck // returned to pool on goroutine exit
	var pktID uint16
	for {
		select {
		case <-cs.qconn.Context().Done():
			return
		default:
		}

		n, srcAddr, err := sess.udpConn.ReadFromUDP(buf)
		if err != nil {
			logger.Warn("[tuic-outbound] ReadFromUDP error assocID=%d: %v", assocID, err)
			return
		}
		logger.Debug("[tuic-outbound] ← target assocID=%d size=%d src=%s", assocID, n, srcAddr)

		sess.touch()
		cs.ob.stats.bytesOut.Add(int64(n))
		// use buf slice directly; writePacketBytes copies data internally
		data := buf[:n]

		// build response Packet command; ADDR uses the real source address
		var addr tuicAddr
		if srcAddr != nil {
			addr = udpAddrToTUIC(srcAddr)
		} else {
			addr = tuicAddr{typ: addrNone, port: 0}
		}

		pkt := tuicPacket{
			assocID:   assocID,
			pktID:     pktID,
			fragTotal: 1,
			fragID:    0,
			size:      uint16(n),
			addr:      addr,
			data:      data,
		}
		pktID++

		// push back to inbound via datagram (auto-fragment if exceeding maxDatagramPayload)
		if err := sendDatagramPkt(cs.qconn, pkt); err != nil {
			logger.Warn("[tuic-outbound] sendDatagramPkt error assocID=%d: %v", assocID, err)
			return
		}
		logger.Debug("[tuic-outbound] -> Packet(dgram) assocID=%d pktID=%d size=%d",
			assocID, pkt.pktID, n)
	}
}

func (ob *Outbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[tuic-outbound:%s] stats | total: %d  active: %d  rx: %s  tx: %s",
			ob.cfg.Listen,
			ob.stats.totalConns.Load(),
			ob.stats.activeConns.Load(),
			util.FormatBytes(ob.stats.bytesIn.Load()),
			util.FormatBytes(ob.stats.bytesOut.Load()),
		)
	}
}
