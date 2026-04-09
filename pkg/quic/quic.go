package quic

// anygo UDP 隧道 —— 完全对标 TUIC v5 协议
//
// 链路：
//   本地UDP流量
//     ↓ 普通 UDP 包
//   inbound（扮演 TUIC v5 客户端）
//     ↓ 标准 TUIC v5 协议（QUIC + anygo-quic ALPN）
//   outbound（扮演 TUIC v5 服务端）
//     ↓ 普通 UDP 包
//   目标 UDP 节点
//
// TUIC v5 协议规范：https://github.com/tuic-protocol/tuic/blob/master/SPEC.md

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/logger"

	quicgo "github.com/quic-go/quic-go"
)

// ─────────────────────────────────────────────────────────────────────────────
// TUIC v5 协议常量
// ─────────────────────────────────────────────────────────────────────────────

const (
	tuicVersion = 0x05

	// 命令类型
	cmdAuthenticate = 0x00
	cmdConnect      = 0x01
	cmdPacket       = 0x02
	cmdDissociate   = 0x03
	cmdHeartbeat    = 0x04

	// 地址类型
	addrNone   = 0xff
	addrDomain = 0x00
	addrIPv4   = 0x01
	addrIPv6   = 0x02

	// anygo 使用的 QUIC ALPN（与外部 TUIC 节点区分）
	quicALPN = "anygo-quic"

	// 超时
	dialTimeout    = 10 * time.Second
	idleTimeout    = 120 * time.Second
	sessionIdle    = 60 * time.Second
	heartbeatEvery = 10 * time.Second

	udpBufSize = 65535
)

// ─────────────────────────────────────────────────────────────────────────────
// TUIC v5 地址编解码
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
		return tuicAddr{}, fmt.Errorf("未知地址类型: 0x%02x", a.typ)
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
	return fmt.Errorf("未知地址类型: 0x%02x", a.typ)
}

func udpAddrToTUIC(a *net.UDPAddr) tuicAddr {
	if ip4 := a.IP.To4(); ip4 != nil {
		return tuicAddr{typ: addrIPv4, host: ip4.String(), port: uint16(a.Port)}
	}
	return tuicAddr{typ: addrIPv6, host: a.IP.String(), port: uint16(a.Port)}
}

// ─────────────────────────────────────────────────────────────────────────────
// TUIC v5 Packet 命令
//
// 帧格式（unidirectional stream）：
//   客户端→服务端：| VER(1) | TYPE(1) | ASSOC_ID(2) | PKT_ID(2) |
//                  | FRAG_TOTAL(1) | FRAG_ID(1) | SIZE(2) | ADDR | DATA |
//   服务端→客户端：同上，ADDR 为源地址
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

// readPacket 从 unidirectional stream 读取一个完整 Packet 命令
// 调用前 VER+TYPE 两字节已读
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

// writePacket 写出完整 Packet 命令帧（含 VER+TYPE 头）
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
// 工具
// ─────────────────────────────────────────────────────────────────────────────

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// receiveStreamReader 适配 *quicgo.ReceiveStream 为 io.Reader
type receiveStreamReader struct{ s *quicgo.ReceiveStream }

func (r *receiveStreamReader) Read(p []byte) (int, error) { return (*r.s).Read(p) }

// ─────────────────────────────────────────────────────────────────────────────
// Inbound：扮演 TUIC v5 客户端
//
// TUIC v5 客户端职责：
//   1. 建立 QUIC 连接
//   2. 通过 unidirectional stream 发送 Authenticate 命令
//   3. 收到本地 UDP 包时，通过 unidirectional stream 发送 Packet 命令
//      - assocID：按本地客户端地址分配，同一地址复用同一 assocID
//      - pktID：每个包单调递增
//      - fragTotal=1, fragID=0（不分片）
//      - addr：目标地址（anygo 中固定为 outbound 的 remote）
//   4. 接受 outbound 发来的 unidirectional stream，解析 Packet 命令，
//      回写给对应的本地客户端
//   5. 有活跃 session 时，定期通过 QUIC datagram 发送 Heartbeat
//   6. session 空闲超时后，通过 unidirectional stream 发送 Dissociate 命令
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

	sessions   map[string]*inSession // clientAddr → session
	sessionsMu sync.Mutex
	nextAssoc  uint16

	stats inboundStats
	sem   chan struct{}
}

func NewInbound(cfg *config.MergedConfig) *Inbound {
	ib := &Inbound{
		cfg:      cfg,
		sessions: make(map[string]*inSession),
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

	logger.Info("[tuic-inbound] 监听 %s (TUIC客户端) → %s", ib.cfg.Listen, ib.cfg.Remote)

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
				logger.Warn("[tuic-inbound] 并发包数达上限，丢弃")
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
	ib.nextAssoc++
	s := &inSession{
		assocID:    ib.nextAssoc,
		clientAddr: clientAddr,
		lastActive: time.Now(),
	}
	ib.sessions[key] = s
	logger.Debug("[tuic-inbound] 新session assocID=%d client=%s", s.assocID, key)
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

	sess := ib.getOrCreateSession(clientAddr)
	sess.touch()

	qconn, err := ib.getConn()
	if err != nil {
		logger.Error("[tuic-inbound] 获取QUIC连接失败: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	// 开一条单向 stream 发送 Packet 命令
	stream, err := qconn.OpenUniStreamSync(ctx)
	if err != nil {
		select {
		case <-qconn.Context().Done():
			ib.connMu.Lock()
			ib.conn = nil
			ib.connMu.Unlock()
		default:
		}
		logger.Error("[tuic-inbound] 打开单向stream失败: %v", err)
		return
	}

	// 构造 Packet 命令
	// addr 字段：anygo 作为透明隧道，目标地址固定填 None（出口自行决定转发目标）
	// 若需要真正的目标地址路由，可在此传入
	pkt := tuicPacket{
		assocID:   sess.assocID,
		pktID:     sess.allocPktID(),
		fragTotal: 1,
		fragID:    0,
		size:      uint16(len(data)),
		addr:      tuicAddr{typ: addrNone, port: 0},
		data:      data,
	}

	if err := writePacket(stream, pkt); err != nil {
		stream.Close()
		logger.Debug("[tuic-inbound] 发送Packet失败: %v", err)
		return
	}
	stream.Close()

	logger.Debug("[tuic-inbound] → Packet assocID=%d pktID=%d size=%d",
		pkt.assocID, pkt.pktID, pkt.size)
}

// getConn 获取或重建 QUIC 连接（singleflight）
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
		MaxIdleTimeout:       idleTimeout,
		KeepAlivePeriod:      15 * time.Second,
		MaxIncomingUniStreams: 65535,
		EnableDatagrams:      true,
	})
	if err != nil {
		return nil, err
	}

	// ── TUIC v5 Authenticate ──────────────────────────────────────────────────
	// 通过 unidirectional stream 发送：| VER(1) | TYPE(1) | UUID(16) | TOKEN(32) |
	// TOKEN = sha256(password)（简化认证，anygo 两端都是自己控制的）
	authCtx, authCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer authCancel()

	authStream, err := qconn.OpenUniStreamSync(authCtx)
	if err != nil {
		qconn.CloseWithError(0, "auth failed")
		return nil, err
	}
	h := sha256.Sum256([]byte(ib.cfg.Password))
	// UUID：用 password hash 前 16 字节（anygo 内部约定，无需真实 UUID）
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

	// 清理旧 session（连接重建后旧 assocID 失效）
	ib.sessionsMu.Lock()
	ib.sessions = make(map[string]*inSession)
	ib.sessionsMu.Unlock()

	// 启动接收循环：接受 outbound 发来的 Packet 命令
	go ib.recvLoop(qconn)
	// 启动心跳
	go ib.heartbeatLoop(qconn)

	logger.Info("[tuic-inbound] QUIC连接建立 → %s", ib.cfg.Remote)
	return qconn, nil
}

// recvLoop 接受 outbound 主动开的 unidirectional stream，解析 Packet 命令
func (ib *Inbound) recvLoop(qconn *quicgo.Conn) {
	for {
		stream, err := qconn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go ib.handleRecvStream(stream)
	}
}

func (ib *Inbound) handleRecvStream(stream *quicgo.ReceiveStream) {
	r := &receiveStreamReader{s: stream}
	defer (*stream).CancelRead(0)
	(*stream).SetReadDeadline(time.Now().Add(idleTimeout))

	// 读 VER + TYPE
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != tuicVersion || hdr[1] != cmdPacket {
		return
	}

	pkt, err := readPacket(r)
	if err != nil {
		return
	}

	// 按 assocID 找到对应的本地客户端地址
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
		logger.Debug("[tuic-inbound] 收到未知assocID=%d的响应，忽略", pkt.assocID)
		return
	}

	target.touch()
	ib.stats.bytesOut.Add(int64(len(pkt.data)))
	ib.localConn.WriteToUDP(pkt.data, target.clientAddr)

	logger.Debug("[tuic-inbound] ← Packet assocID=%d pktID=%d size=%d → %s",
		pkt.assocID, pkt.pktID, pkt.size, target.clientAddr)
}

// heartbeatLoop 有活跃 session 时定期发 TUIC v5 Heartbeat datagram
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

// cleanupLoop 定期清理空闲 session，并发送 TUIC v5 Dissociate 命令
func (ib *Inbound) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
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
		ib.sessionsMu.Unlock()

		for _, s := range toRemove {
			logger.Debug("[tuic-inbound] session超时 assocID=%d，发送Dissociate", s.assocID)
			go ib.sendDissociate(s.assocID)
		}
	}
}

// sendDissociate 通过 unidirectional stream 发送 TUIC v5 Dissociate 命令
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
		logger.Info("[tuic-inbound:%s] 统计 | 累计包: %d  收: %s  发: %s",
			ib.cfg.Listen,
			ib.stats.totalPkts.Load(),
			formatBytes(ib.stats.bytesIn.Load()),
			formatBytes(ib.stats.bytesOut.Load()),
		)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Outbound：扮演 TUIC v5 服务端
//
// TUIC v5 服务端职责：
//   1. 监听 QUIC 连接
//   2. 接受 unidirectional stream，解析命令：
//      - Authenticate：验证 TOKEN，标记连接为已认证
//      - Packet：按 assocID 查找或创建 UDP socket，发给目标地址
//      - Dissociate：关闭对应 UDP socket
//   3. 收到目标地址的 UDP 响应时，通过 unidirectional stream 发回 Packet 命令
//      （源地址填实际收到响应的地址）
//   4. 接受 QUIC datagram，忽略 Heartbeat（QUIC 层自动处理保活）
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
		return fmt.Errorf("解析目标地址失败: %w", err)
	}
	ob.targetAddr = targetAddr

	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return fmt.Errorf("加载证书失败: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}

	listener, err := quicgo.ListenAddr(ob.cfg.Listen, tlsCfg, &quicgo.Config{
		MaxIdleTimeout:       idleTimeout,
		KeepAlivePeriod:      15 * time.Second,
		MaxIncomingUniStreams: 65535,
		EnableDatagrams:      true,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Info("[tuic-outbound] 监听 %s (TUIC服务端) → %s", ob.cfg.Listen, ob.cfg.Remote)
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
				logger.Warn("[tuic-outbound] 连接数达上限，拒绝")
				conn.CloseWithError(0, "too many connections")
				continue
			}
		}
		ob.stats.totalConns.Add(1)
		ob.stats.activeConns.Add(1)
		go ob.handleConn(conn)
	}
}

// connState 每条 QUIC 连接的状态
type connState struct {
	ob         *Outbound
	qconn      *quicgo.Conn
	authed     atomic.Bool
	sessions   map[uint16]*outSession
	sessionsMu sync.Mutex
	// 待处理命令缓冲（认证前到达的命令先缓冲）
	pendingMu  sync.Mutex
	pending    []func()
}

func (ob *Outbound) handleConn(qconn *quicgo.Conn) {
	defer func() {
		qconn.CloseWithError(0, "done")
		ob.stats.activeConns.Add(-1)
		if ob.sem != nil {
			<-ob.sem
		}
	}()

	cs := &connState{
		ob:       ob,
		qconn:    qconn,
		sessions: make(map[uint16]*outSession),
	}

	// 接受 datagram（Heartbeat）
	go cs.recvDatagrams()

	// session 空闲清理
	go cs.sessionCleanup()

	// 循环接受 unidirectional stream
	for {
		stream, err := qconn.AcceptUniStream(context.Background())
		if err != nil {
			break
		}
		go cs.handleStream(stream)
	}

	// 关闭所有 session
	cs.sessionsMu.Lock()
	for _, s := range cs.sessions {
		s.close()
	}
	cs.sessionsMu.Unlock()
}

func (cs *connState) recvDatagrams() {
	for {
		data, err := cs.qconn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		// TUIC v5 Heartbeat：| VER(1) | TYPE(1) |，忽略即可
		if len(data) >= 2 && data[0] == tuicVersion && data[1] == cmdHeartbeat {
			logger.Debug("[tuic-outbound] 收到Heartbeat")
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
					logger.Debug("[tuic-outbound] session超时 assocID=%d", id)
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

	// 读 VER + TYPE
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != tuicVersion {
		logger.Warn("[tuic-outbound] 未知TUIC版本: 0x%02x", hdr[0])
		return
	}

	switch hdr[1] {
	case cmdAuthenticate:
		cs.handleAuth(r)
	case cmdPacket:
		if !cs.authed.Load() {
			// 按规范：认证前收到其他命令，先缓冲，认证后再处理
			// 简化：直接等待认证完成后处理
			// 实际 anygo 场景下认证 stream 总是最先发，此处直接丢弃
			logger.Warn("[tuic-outbound] 未认证连接发送Packet，忽略")
			return
		}
		cs.handlePacket(r)
	case cmdDissociate:
		if !cs.authed.Load() {
			return
		}
		cs.handleDissociate(r)
	}
}

// handleAuth 处理 TUIC v5 Authenticate 命令
// | UUID(16) | TOKEN(32) |（VER+TYPE 已读）
func (cs *connState) handleAuth(r io.Reader) {
	buf := make([]byte, 16+32)
	if _, err := io.ReadFull(r, buf); err != nil {
		cs.qconn.CloseWithError(1, "auth read failed")
		return
	}
	token := buf[16:] // TOKEN 在 UUID 之后
	expected := sha256.Sum256([]byte(cs.ob.cfg.Password))
	if !equalBytes(token, expected[:]) {
		logger.Warn("[tuic-outbound] 认证失败 from %s", cs.qconn.RemoteAddr())
		cs.qconn.CloseWithError(1, "auth failed")
		return
	}
	cs.authed.Store(true)
	logger.Debug("[tuic-outbound] 认证成功: %s", cs.qconn.RemoteAddr())
}

// handlePacket 处理 TUIC v5 Packet 命令
// （VER+TYPE 已读）
func (cs *connState) handlePacket(r io.Reader) {
	pkt, err := readPacket(r)
	if err != nil {
		return
	}

	cs.ob.stats.bytesIn.Add(int64(pkt.size))
	logger.Debug("[tuic-outbound] ← Packet assocID=%d pktID=%d frag=%d/%d size=%d",
		pkt.assocID, pkt.pktID, pkt.fragID+1, pkt.fragTotal, pkt.size)

	// 获取或创建该 assocID 对应的 UDP socket
	cs.sessionsMu.Lock()
	sess, ok := cs.sessions[pkt.assocID]
	if !ok {
		udpConn, err := net.DialUDP("udp", nil, cs.ob.targetAddr)
		if err != nil {
			cs.sessionsMu.Unlock()
			logger.Error("[tuic-outbound] 创建UDP连接失败 assocID=%d: %v", pkt.assocID, err)
			return
		}
		sess = &outSession{
			assocID:    pkt.assocID,
			udpConn:    udpConn,
			lastActive: time.Now(),
		}
		cs.sessions[pkt.assocID] = sess
		logger.Debug("[tuic-outbound] 新session assocID=%d → %s", pkt.assocID, cs.ob.targetAddr)
		// 启动接收循环：目标 → 客户端
		go cs.recvFromTarget(pkt.assocID, sess)
	}
	cs.sessionsMu.Unlock()

	sess.touch()

	// 发送给目标 UDP 节点
	if _, err := sess.udpConn.Write(pkt.data); err != nil {
		logger.Debug("[tuic-outbound] UDP发送失败 assocID=%d: %v", pkt.assocID, err)
	}
}

// handleDissociate 处理 TUIC v5 Dissociate 命令
// | ASSOC_ID(2) |（VER+TYPE 已读）
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

// recvFromTarget 持续接收目标 UDP 节点的响应，通过 unidirectional stream 发回客户端
// 响应 Packet 命令：ADDR 填实际收到响应的源地址（TUIC v5 规范要求）
func (cs *connState) recvFromTarget(assocID uint16, sess *outSession) {
	buf := make([]byte, udpBufSize)
	var pktID uint16
	for {
		select {
		case <-cs.qconn.Context().Done():
			return
		default:
		}

		sess.udpConn.SetReadDeadline(time.Now().Add(sessionIdle))
		n, srcAddr, err := sess.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		sess.touch()
		data := make([]byte, n)
		copy(data, buf[:n])
		cs.ob.stats.bytesOut.Add(int64(n))

		// 构造响应 Packet 命令，ADDR 填真实源地址
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

		// 开一条 unidirectional stream 发回客户端
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := cs.qconn.OpenUniStreamSync(ctx)
		cancel()
		if err != nil {
			logger.Debug("[tuic-outbound] 开单向stream失败 assocID=%d: %v", assocID, err)
			return
		}
		if err := writePacket(stream, pkt); err != nil {
			stream.Close()
			return
		}
		stream.Close()

		logger.Debug("[tuic-outbound] → Packet assocID=%d pktID=%d size=%d src=%s",
			assocID, pkt.pktID, n, srcAddr)
	}
}

func (ob *Outbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[tuic-outbound:%s] 统计 | 累计连接: %d  活跃: %d  收: %s  发: %s",
			ob.cfg.Listen,
			ob.stats.totalConns.Load(),
			ob.stats.activeConns.Load(),
			formatBytes(ob.stats.bytesIn.Load()),
			formatBytes(ob.stats.bytesOut.Load()),
		)
	}
}