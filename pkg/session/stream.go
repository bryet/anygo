package session

import (
	"io"
	"net"
	"sync"
	"time"
)

type streamState int

const (
	streamOpen   streamState = iota
	streamClosed streamState = iota

	// maxReadBufSize is the maximum read buffer size per stream.
	// When exceeded, the stream is closed to signal backpressure to the sender.
	// 4 MB is large enough for most TCP workloads while preventing OOM.
	defaultMaxReadBufSize = 4 * 1024 * 1024
)

// MaxReadBufSize is the per-stream read buffer limit. Set to 0 for unlimited.
// Can be adjusted at startup based on expected workload.
var MaxReadBufSize = defaultMaxReadBufSize

// Stream: virtual connection over a multiplexed Session, implements net.Conn
//
// lock ordering rules (to avoid deadlocks):
//
//	stateMu and readMu are never held at the same time.
//	When Read checks state: release readMu → acquire stateMu → release stateMu → re-acquire readMu
type Stream struct {
	id      uint32
	session *Session

	readBuf  []byte
	readMu   sync.Mutex
	readCond *sync.Cond

	state   streamState
	stateMu sync.Mutex

	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMu    sync.RWMutex

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

func (s *Stream) pushData(data []byte) {
	s.readMu.Lock()

	if MaxReadBufSize > 0 && len(s.readBuf)+len(data) > MaxReadBufSize {
		// Buffer overflow — close the stream to prevent OOM.
		// Release readMu before closeByRemote to avoid lock ordering issues.
		s.readMu.Unlock()
		s.closeByRemote()
		return
	}

	defer s.readMu.Unlock()
	s.readBuf = append(s.readBuf, data...)
	s.readCond.Signal()
}

// Read implements net.Conn
// fix: temporarily release readMu when checking state, to avoid lock ordering conflict with Close/closeByRemote
// timer created once outside the loop and reused to avoid repeated allocation
func (s *Stream) Read(buf []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		// if data is available, return immediately
		if len(s.readBuf) > 0 {
			n := copy(buf, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}

		// fix: release readMu before checking state; acquire stateMu separately without holding both locks
		s.readMu.Unlock()
		s.stateMu.Lock()
		closed := s.state == streamClosed
		s.stateMu.Unlock()
		s.readMu.Lock()

		if closed {
			// after close, check buffer again to ensure pushed data is not lost
			if len(s.readBuf) > 0 {
				n := copy(buf, s.readBuf)
				s.readBuf = s.readBuf[n:]
				return n, nil
			}
			return 0, io.EOF
		}

		// check deadline
		s.deadlineMu.RLock()
		deadline := s.readDeadline
		s.deadlineMu.RUnlock()

		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, &timeoutError{}
			}
			// reuse timer: create on first use, Reset on subsequent uses
			if timer == nil {
				timer = time.AfterFunc(remaining, func() {
					s.readCond.Signal()
				})
			} else {
				timer.Reset(remaining)
			}
			s.readCond.Wait()
			if !deadline.IsZero() && time.Now().After(deadline) {
				return 0, &timeoutError{}
			}
		} else {
			if timer != nil {
				timer.Stop()
				timer = nil
			}
			s.readCond.Wait()
		}
	}
}

// Write implements net.Conn; sends cmdPSH via Session
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

// Close close a Stream, sends cmdFIN
// fix: Signal does not require holding readMu (Cond.Signal is concurrency-safe)
func (s *Stream) Close() error {
	s.once.Do(func() {
		s.stateMu.Lock()
		s.state = streamClosed
		s.stateMu.Unlock()

		s.readCond.Signal()
		s.session.closeStream(s.id)
		close(s.closeCh)
	})
	return nil
}

// closeByRemote is called by Session when receiving cmdFIN from the peer
func (s *Stream) closeByRemote() {
	s.stateMu.Lock()
	s.state = streamClosed
	s.stateMu.Unlock()

	s.readCond.Signal()

	s.once.Do(func() {
		close(s.closeCh)
	})
}

func (s *Stream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }

func (s *Stream) SetDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	if !t.IsZero() && time.Now().After(t) {
		s.readCond.Signal()
	}
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.deadlineMu.Unlock()
	if !t.IsZero() && time.Now().After(t) {
		s.readCond.Signal()
	}
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	return nil
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "deadline exceeded" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }