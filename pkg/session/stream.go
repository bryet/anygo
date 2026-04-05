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
)

// Stream 复用Session上的一条虚拟连接，实现net.Conn接口
//
// 锁顺序规范（避免死锁）：
//
//	stateMu 和 readMu 永远不同时持有。
//	Read 检查 state 时：临时释放 readMu → 加 stateMu → 释放 stateMu → 重新加 readMu
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
	defer s.readMu.Unlock()
	s.readBuf = append(s.readBuf, data...)
	s.readCond.Signal()
}

// Read 实现net.Conn
// 修复：检查 state 时临时释放 readMu，避免与 Close/closeByRemote 的锁顺序冲突
// timer 在循环外创建一次并复用，避免重复分配
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
		// 有数据直接返回
		if len(s.readBuf) > 0 {
			n := copy(buf, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}

		// 修复：检查 state 时先释放 readMu，单独加 stateMu，不嵌套持有两个锁
		s.readMu.Unlock()
		s.stateMu.Lock()
		closed := s.state == streamClosed
		s.stateMu.Unlock()
		s.readMu.Lock()

		if closed {
			// 关闭后再检查一次缓冲，确保已推送的数据不丢失
			if len(s.readBuf) > 0 {
				n := copy(buf, s.readBuf)
				s.readBuf = s.readBuf[n:]
				return n, nil
			}
			return 0, io.EOF
		}

		// 检查 deadline
		s.deadlineMu.RLock()
		deadline := s.readDeadline
		s.deadlineMu.RUnlock()

		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, &timeoutError{}
			}
			// 复用 timer：第一次创建，后续 Reset
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
// 修复：Signal 不需要持有 readMu（Cond.Signal 是并发安全的）
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

// closeByRemote 由Session在收到对端cmdFIN时调用
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