package session

import (
	"io"
	"net"
	"sync"
	"time"
)

// streamState Stream状态
type streamState int

const (
	streamOpen   streamState = iota
	streamClosed streamState = iota
)

// Stream 复用Session上的一条虚拟连接，实现net.Conn接口
type Stream struct {
	id      uint32
	session *Session

	// 读缓冲：服务端收到的cmdPSH数据放这里
	readBuf  []byte
	readMu   sync.Mutex
	readCond *sync.Cond

	state   streamState
	stateMu sync.Mutex

	readDeadline  time.Time
	writeDeadline time.Time

	// 通知Stream已关闭
	closeCh chan struct{}
	once    sync.Once
}

func newStream(id uint32, sess *Session) *Stream {
	s := &Stream{
		id:      id,
		session: sess,
		state:   streamOpen,
		closeCh: make(chan struct{}),
	}
	s.readCond = sync.NewCond(&s.readMu)
	return s
}

func (s *Stream) ID() uint32 {
	return s.id
}

// pushData 将收到的cmdPSH数据放入读缓冲（由Session调用）
func (s *Stream) pushData(data []byte) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.readBuf = append(s.readBuf, data...)
	s.readCond.Signal()
}

// Read 实现net.Conn
func (s *Stream) Read(buf []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		if len(s.readBuf) > 0 {
			n := copy(buf, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}

		s.stateMu.Lock()
		closed := s.state == streamClosed
		s.stateMu.Unlock()

		if closed {
			return 0, io.EOF
		}

		// 检查deadline
		if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
			return 0, &timeoutError{}
		}

		s.readCond.Wait()
	}
}

// Write 实现net.Conn，通过Session发送cmdPSH
func (s *Stream) Write(data []byte) (int, error) {
	s.stateMu.Lock()
	if s.state == streamClosed {
		s.stateMu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.stateMu.Unlock()

	if err := s.session.writeData(s.id, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Close 关闭Stream，发送cmdFIN
func (s *Stream) Close() error {
	s.once.Do(func() {
		s.stateMu.Lock()
		s.state = streamClosed
		s.stateMu.Unlock()

		// 唤醒阻塞的Read
		s.readMu.Lock()
		s.readCond.Signal()
		s.readMu.Unlock()

		// 通知Session发送cmdFIN
		s.session.closeStream(s.id)

		close(s.closeCh)
	})
	return nil
}

// closeByRemote 由Session在收到对端cmdFIN时调用
func (s *Stream) closeByRemote() {
	s.stateMu.Lock()
	s.state = streamClosed
	s.stateMu.Unlock()

	s.readMu.Lock()
	s.readCond.Signal()
	s.readMu.Unlock()

	s.once.Do(func() {
		close(s.closeCh)
	})
}

func (s *Stream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }

func (s *Stream) SetDeadline(t time.Time) error {
	s.readDeadline = t
	s.writeDeadline = t
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline = t
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline = t
	return nil
}

// timeoutError 超时错误
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "deadline exceeded" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
