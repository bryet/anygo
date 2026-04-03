package session

import (
	"log"
	"sort"
	"sync"
	"time"
)

// Pool 客户端空闲Session池
// 策略：优先复用最新（Seq最大）的Session，优先清理最老的Session
type Pool struct {
	mu       sync.Mutex
	sessions []*ClientSession
	nextSeq  uint64

	// 配置
	checkInterval  time.Duration
	idleTimeout    time.Duration
	minIdleSession int

	// 新建Session的工厂函数（由inbound注入）
	dial func() (*ClientSession, error)

	done chan struct{}
}

// NewPool 创建Session池
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
func (p *Pool) GetStream() (*Stream, *ClientSession, error) {
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
		// 从空闲列表移除（它现在是busy状态）
		p.sessions = append(p.sessions[:bestIdx], p.sessions[bestIdx+1:]...)
		p.mu.Unlock()

		stream, err := best.OpenStream()
		if err != nil {
			// stream失败，Session可能已坏
			best.close(err)
			return p.GetStream() // 递归重试
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

	// 先过滤掉已关闭的
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
		// 保留前minIdleSession个不清理
		if i < p.minIdleSession {
			kept = append(kept, cs)
			continue
		}
		// 超过idleTimeout的清理掉
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
