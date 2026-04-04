package session

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anygo/pkg/frame"
	"anygo/pkg/padding"
)

const (
	protoVersion = 2
	clientName   = "anygo/0.1.0"

	heartbeatInterval = 30 * time.Second
	heartbeatTimeout  = 10 * time.Second
	synackTimeout     = 15 * time.Second
)

// Session 一个复用的TLS连接上的会话
type Session struct {
	conn     net.Conn
	isClient bool

	streams   map[uint32]*Stream
	streamsMu sync.Mutex

	nextStreamID uint32

	writeMu sync.Mutex

	paddingScheme *padding.Scheme
	pktCounter    int
	pktMu         sync.Mutex

	remoteVersion int

	synackWaiters   map[uint32]chan error
	synackWaitersMu sync.Mutex

	lastHeartbeat time.Time
	heartMu       sync.Mutex

	closed    chan struct{}
	closeOnce sync.Once
	err       error
}

func newSession(conn net.Conn, isClient bool, scheme *padding.Scheme) *Session {
	s := &Session{
		conn:          conn,
		isClient:      isClient,
		streams:       make(map[uint32]*Stream),
		paddingScheme: scheme,
		synackWaiters: make(map[uint32]chan error),
		closed:        make(chan struct{}),
		lastHeartbeat: time.Now(),
	}
	if isClient {
		s.nextStreamID = 0
	}
	return s
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Session) close(err error) {
	s.closeOnce.Do(func() {
		s.err = err
		close(s.closed)
		s.conn.Close()

		s.streamsMu.Lock()
		for _, st := range s.streams {
			st.closeByRemote()
		}
		s.streamsMu.Unlock()

		s.synackWaitersMu.Lock()
		for _, ch := range s.synackWaiters {
			select {
			case ch <- fmt.Errorf("session closed"):
			default:
			}
		}
		s.synackWaitersMu.Unlock()
	})
}

func (s *Session) writeFrame(cmd uint8, streamID uint32, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return frame.WriteFrame(s.conn, cmd, streamID, data)
}

func (s *Session) writeData(streamID uint32, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.pktMu.Lock()
	idx := s.pktCounter
	s.pktCounter++
	s.pktMu.Unlock()

	if idx >= s.paddingScheme.Stop {
		return frame.WriteFrame(s.conn, frame.CmdPSH, streamID, data)
	}

	segs, ok := s.paddingScheme.Rules[idx]
	if !ok || len(segs) == 0 {
		return frame.WriteFrame(s.conn, frame.CmdPSH, streamID, data)
	}

	return s.applyPadding(streamID, data, segs)
}

func (s *Session) applyPadding(streamID uint32, data []byte, segs []padding.Segment) error {
	offset := 0

	for _, seg := range segs {
		if seg.Check {
			if offset >= len(data) {
				return nil
			}
			continue
		}

		targetSize := padding.RandInRange(seg.Min, seg.Max)

		if offset < len(data) {
			end := offset + targetSize
			if end > len(data) {
				end = len(data)
			}
			if err := frame.WriteFrame(s.conn, frame.CmdPSH, streamID, data[offset:end]); err != nil {
				return err
			}
			offset = end
		} else {
			waste := padding.RandBytes(targetSize)
			if err := frame.WriteFrame(s.conn, frame.CmdWaste, 0, waste); err != nil {
				return err
			}
		}
	}

	if offset < len(data) {
		return frame.WriteFrame(s.conn, frame.CmdPSH, streamID, data[offset:])
	}
	return nil
}

func (s *Session) closeStream(streamID uint32) {
	if !s.IsClosed() {
		s.writeFrame(frame.CmdFIN, streamID, nil)
	}
	s.streamsMu.Lock()
	delete(s.streams, streamID)
	s.streamsMu.Unlock()
}

func (s *Session) recvLoop() {
	for {
		f, err := frame.ReadFrame(s.conn)
		if err != nil {
			s.close(err)
			return
		}
		if err := s.handleFrame(f); err != nil {
			s.close(err)
			return
		}
	}
}

func (s *Session) handleFrame(f *frame.Frame) error {
	switch f.Command {
	case frame.CmdWaste:
		// 无声丢弃

	case frame.CmdPSH:
		s.streamsMu.Lock()
		st, ok := s.streams[f.StreamID]
		s.streamsMu.Unlock()
		if ok {
			st.pushData(f.Data)
		}

	case frame.CmdFIN:
		s.streamsMu.Lock()
		st, ok := s.streams[f.StreamID]
		if ok {
			delete(s.streams, f.StreamID)
		}
		s.streamsMu.Unlock()
		if ok {
			st.closeByRemote()
		}

	case frame.CmdAlert:
		log.Printf("[session] alert: %s", string(f.Data))
		return fmt.Errorf("remote alert: %s", string(f.Data))

	case frame.CmdUpdatePaddingScheme:
		scheme, err := padding.Parse(string(f.Data))
		if err != nil {
			log.Printf("[session] invalid padding scheme: %v", err)
			return nil
		}
		s.paddingScheme = scheme
		log.Printf("[session] padding scheme updated md5=%s", scheme.MD5())

	case frame.CmdSYNACK:
		s.synackWaitersMu.Lock()
		ch, ok := s.synackWaiters[f.StreamID]
		if ok {
			delete(s.synackWaiters, f.StreamID)
		}
		s.synackWaitersMu.Unlock()
		if ok {
			var err error
			if len(f.Data) > 0 {
				err = fmt.Errorf("%s", string(f.Data))
			}
			select {
			case ch <- err:
			default:
			}
		}

	case frame.CmdHeartRequest:
		s.writeFrame(frame.CmdHeartResponse, 0, nil)

	case frame.CmdHeartResponse:
		s.heartMu.Lock()
		s.lastHeartbeat = time.Now()
		s.heartMu.Unlock()

	case frame.CmdServerSettings:
		settings := parseSettings(f.Data)
		if v, ok := settings["v"]; ok {
			var ver int
			fmt.Sscanf(v, "%d", &ver)
			s.remoteVersion = ver
			log.Printf("[session] server version=%d", ver)
		}
	}
	return nil
}

func (s *Session) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			if err := s.writeFrame(frame.CmdHeartRequest, 0, nil); err != nil {
				s.close(err)
				return
			}
			s.heartMu.Lock()
			last := s.lastHeartbeat
			s.heartMu.Unlock()
			if time.Since(last) > heartbeatInterval+heartbeatTimeout {
				s.close(fmt.Errorf("heartbeat timeout"))
				return
			}
		}
	}
}

func parseSettings(data []byte) map[string]string {
	result := make(map[string]string)
	s := string(data)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			line := s[start:i]
			start = i + 1
			for j := 0; j < len(line); j++ {
				if line[j] == '=' {
					result[line[:j]] = line[j+1:]
					break
				}
			}
		}
	}
	return result
}

// ─────────────────────────────────────────────────
// ClientSession
// ─────────────────────────────────────────────────

type ClientSession struct {
	*Session
	seq    uint64
	idleAt time.Time
	isIdle bool
	idleMu sync.Mutex
}

func NewClientSession(conn net.Conn, password string, scheme *padding.Scheme) (*ClientSession, error) {
	cs := &ClientSession{
		Session: newSession(conn, true, scheme),
	}

	settingsData := buildClientSettings(scheme)
	if err := cs.writeFrame(frame.CmdSettings, 0, settingsData); err != nil {
		return nil, err
	}

	// cmdSettings 占用了包1的计数（与首个cmdSYN+cmdPSH合并为包1）
	// 因此后续 writeData 从包2开始计，与协议定义一致
	cs.pktCounter = 1

	go cs.recvLoop()
	go cs.heartbeatLoop()

	return cs, nil
}

func buildClientSettings(scheme *padding.Scheme) []byte {
	s := fmt.Sprintf("v=%d\nclient=%s\npadding-md5=%s", protoVersion, clientName, scheme.MD5())
	return []byte(s)
}

func (cs *ClientSession) OpenStream() (*Stream, error) {
	if cs.IsClosed() {
		return nil, fmt.Errorf("session closed")
	}

	streamID := atomic.AddUint32(&cs.nextStreamID, 1)
	st := newStream(streamID, cs.Session)

	cs.streamsMu.Lock()
	cs.streams[streamID] = st
	cs.streamsMu.Unlock()

	if err := cs.writeFrame(frame.CmdSYN, streamID, nil); err != nil {
		cs.streamsMu.Lock()
		delete(cs.streams, streamID)
		cs.streamsMu.Unlock()
		return nil, err
	}

	// v2: 等待SYNACK
	if cs.remoteVersion >= 2 {
		ch := make(chan error, 1)
		cs.synackWaitersMu.Lock()
		cs.synackWaiters[streamID] = ch
		cs.synackWaitersMu.Unlock()

		select {
		case err := <-ch:
			if err != nil {
				st.Close()
				return nil, err
			}
		case <-time.After(synackTimeout):
			cs.synackWaitersMu.Lock()
			delete(cs.synackWaiters, streamID)
			cs.synackWaitersMu.Unlock()
			st.Close()
			return nil, fmt.Errorf("synack timeout stream=%d", streamID)
		case <-cs.closed:
			return nil, fmt.Errorf("session closed")
		}
	}

	return st, nil
}

func (cs *ClientSession) SetIdle() {
	cs.idleMu.Lock()
	cs.isIdle = true
	cs.idleAt = time.Now()
	cs.idleMu.Unlock()
}

func (cs *ClientSession) SetBusy() {
	cs.idleMu.Lock()
	cs.isIdle = false
	cs.idleMu.Unlock()
}

func (cs *ClientSession) IsIdle() bool {
	cs.idleMu.Lock()
	defer cs.idleMu.Unlock()
	return cs.isIdle
}

func (cs *ClientSession) IdleSince() time.Time {
	cs.idleMu.Lock()
	defer cs.idleMu.Unlock()
	return cs.idleAt
}

// ─────────────────────────────────────────────────
// ServerSession
// ─────────────────────────────────────────────────

type ServerSession struct {
	*Session
	acceptCh chan *Stream
}

func NewServerSession(conn net.Conn, serverScheme *padding.Scheme) (*ServerSession, error) {
	ss := &ServerSession{
		Session:  newSession(conn, false, serverScheme),
		acceptCh: make(chan *Stream, 64),
	}

	settingsCh := make(chan map[string]string, 1)
	go ss.serverRecvLoop(settingsCh)

	select {
	case settings := <-settingsCh:
		if err := ss.handleClientSettings(settings, serverScheme); err != nil {
			ss.close(err)
			return nil, err
		}
	case <-time.After(15 * time.Second):
		ss.close(fmt.Errorf("settings timeout"))
		return nil, fmt.Errorf("settings timeout")
	case <-ss.closed:
		return nil, fmt.Errorf("session closed during handshake")
	}

	return ss, nil
}

func (ss *ServerSession) handleClientSettings(settings map[string]string, serverScheme *padding.Scheme) error {
	clientVersion := 1
	if v, ok := settings["v"]; ok {
		fmt.Sscanf(v, "%d", &clientVersion)
	}
	ss.remoteVersion = clientVersion

	if clientMD5, ok := settings["padding-md5"]; ok {
		if clientMD5 != serverScheme.MD5() {
			log.Printf("[server-session] padding mismatch, sending update (client=%s server=%s)", clientMD5, serverScheme.MD5())
			if err := ss.writeFrame(frame.CmdUpdatePaddingScheme, 0, []byte(serverScheme.Raw())); err != nil {
				return err
			}
		}
	}

	if clientVersion >= 2 {
		data := []byte(fmt.Sprintf("v=%d", protoVersion))
		if err := ss.writeFrame(frame.CmdServerSettings, 0, data); err != nil {
			return err
		}
	}

	log.Printf("[server-session] handshake ok client_version=%d", clientVersion)
	return nil
}

func (ss *ServerSession) serverRecvLoop(settingsCh chan map[string]string) {
	settingsSent := false

	for {
		f, err := frame.ReadFrame(ss.conn)
		if err != nil {
			ss.close(err)
			return
		}

		if !settingsSent {
			if f.Command != frame.CmdSettings {
				ss.writeFrame(frame.CmdAlert, 0, []byte("expected cmdSettings first"))
				ss.close(fmt.Errorf("protocol violation"))
				return
			}
			settingsSent = true
			settingsCh <- parseSettings(f.Data)
			continue
		}

		switch f.Command {
		case frame.CmdSYN:
			st := newStream(f.StreamID, ss.Session)
			ss.streamsMu.Lock()
			ss.streams[f.StreamID] = st
			ss.streamsMu.Unlock()

			if ss.remoteVersion >= 2 {
				sid := f.StreamID
				go ss.writeFrame(frame.CmdSYNACK, sid, nil)
			}

			select {
			case ss.acceptCh <- st:
			default:
				st.closeByRemote()
				ss.writeFrame(frame.CmdFIN, f.StreamID, nil)
			}

		default:
			if err := ss.handleFrame(f); err != nil {
				ss.close(err)
				return
			}
		}
	}
}

func (ss *ServerSession) AcceptStream() (*Stream, error) {
	select {
	case st := <-ss.acceptCh:
		return st, nil
	case <-ss.closed:
		return nil, fmt.Errorf("session closed")
	}
}