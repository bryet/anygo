package session

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

const maxGetStreamRetries = 3

// Pool 客户端空闲Session池
// 策略：优先复用最新（Seq最大）的Session，优先清理最老的Session
type Pool struct {
	mu       sync.Mutex
	sessions []*ClientSession
	nextSeq  uint64

	checkInterval  time.Duration
	idleTimeout    time.Duration
	minIdleSession int

	dial func() (*ClientSession, error)

	done chan struct{}
}

func NewPool(
	dial func() (*ClientSession, error),
	checkInterval time.Duration,
	idleTimeout time.Duration,
	minIdleSession int,
) *Pool {
	p := &Pool{
		dial:           dial,
		checkInterval:  checkInterval,
		idleTimeout:    idleTimeout,
		minIdleSession: minIdleSession,
		done:           make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

// GetStream 获取一个可用的Stream：优先从空闲Session中复用，否则新建Session
// 修复：改为循环重试，避免原来递归调用可能导致的栈溢出
func (p *Pool) GetStream() (*Stream, *ClientSession, error) {
	for attempt := 0; attempt < maxGetStreamRetries; attempt++ {
		stream, cs, err := p.tryGetStream()
		if err == nil {
			return stream, cs, nil
		}
		log.Printf("[pool] GetStream attempt %d failed: %v", attempt+1, err)
	}
	return nil, nil, fmt.Errorf("获取stream失败，已重试%d次", maxGetStreamRetries)
}

// tryGetStream 单次尝试获取Stream
func (p *Pool) tryGetStream() (*Stream, *ClientSession, error) {
	p.mu.Lock()

	// 找Seq最大的空闲Session
	var best *ClientSession
	bestIdx := -1
	for i, cs := range p.sessions {
		if cs.IsClosed() {
			continue
		}
		if cs.IsIdle() {
			if best == nil || cs.seq > best.seq {
				best = cs
				bestIdx = i
			}
		}
	}

	if best != nil {
		best.SetBusy()
		p.sessions = append(p.sessions[:bestIdx], p.sessions[bestIdx+1:]...)
		p.mu.Unlock()

		stream, err := best.OpenStream()
		if err != nil {
			// Session已失效，关闭它，下次会新建
			best.close(err)
			return nil, nil, err
		}
		return stream, best, nil
	}
	p.mu.Unlock()

	// 没有空闲Session，新建
	cs, err := p.newSession()
	if err != nil {
		return nil, nil, err
	}

	stream, err := cs.OpenStream()
	if err != nil {
		cs.close(err)
		return nil, nil, err
	}
	return stream, cs, nil
}

// ReturnSession Stream使用完毕后，将Session放回空闲池
func (p *Pool) ReturnSession(cs *ClientSession) {
	if cs.IsClosed() {
		return
	}
	cs.SetIdle()
	p.mu.Lock()
	p.sessions = append(p.sessions, cs)
	p.mu.Unlock()
}

// newSession 新建一个ClientSession
func (p *Pool) newSession() (*ClientSession, error) {
	cs, err := p.dial()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	cs.seq = p.nextSeq
	p.nextSeq++
	p.mu.Unlock()

	log.Printf("[pool] new session seq=%d", cs.seq)
	return cs, nil
}

// cleanupLoop 定期清理超时的空闲Session
func (p *Pool) cleanupLoop() {
	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.cleanup()
		}
	}
}

func (p *Pool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	var alive []*ClientSession

	for _, cs := range p.sessions {
		if !cs.IsClosed() {
			alive = append(alive, cs)
		}
	}

	// 按Seq从大到小排序（Seq大=最新）
	sort.Slice(alive, func(i, j int) bool {
		return alive[i].seq > alive[j].seq
	})

	var kept []*ClientSession
	for i, cs := range alive {
		if i < p.minIdleSession {
			kept = append(kept, cs)
			continue
		}
		if now.Sub(cs.IdleSince()) > p.idleTimeout {
			log.Printf("[pool] closing idle session seq=%d (idle %v)", cs.seq, now.Sub(cs.IdleSince()))
			cs.close(nil)
		} else {
			kept = append(kept, cs)
		}
	}

	p.sessions = kept
}

// Close 关闭池
func (p *Pool) Close() {
	close(p.done)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cs := range p.sessions {
		cs.close(nil)
	}
}