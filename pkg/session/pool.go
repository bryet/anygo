package session

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

const maxGetStreamRetries = 3

// Pool: client idle session pool
// strategy: prefer the newest (highest Seq) Session; evict oldest first
type Pool struct {
	mu       sync.Mutex
	sessions []*ClientSession
	nextSeq  uint64

	checkInterval  time.Duration
	idleTimeout    time.Duration
	minIdleSession int
	maxIdleSession int // hard cap; 0 = no limit

	dial func() (*ClientSession, error)

	done chan struct{}
}

func NewPool(
	dial func() (*ClientSession, error),
	checkInterval time.Duration,
	idleTimeout time.Duration,
	minIdleSession int,
	maxIdleSession int,
) *Pool {
	p := &Pool{
		dial:           dial,
		checkInterval:  checkInterval,
		idleTimeout:    idleTimeout,
		minIdleSession: minIdleSession,
		maxIdleSession: maxIdleSession,
		done:           make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

// GetStream gets an available Stream, retries in a loop to avoid stack overflow
func (p *Pool) GetStream() (*Stream, *ClientSession, error) {
	for attempt := 0; attempt < maxGetStreamRetries; attempt++ {
		stream, cs, err := p.tryGetStream()
		if err == nil {
			return stream, cs, nil
		}
		log.Printf("[pool] GetStream attempt %d failed: %v", attempt+1, err)
	}
	return nil, nil, fmt.Errorf("get stream failed, after %d retries", maxGetStreamRetries)
}

// tryGetStream makes a single attempt to get a Stream
func (p *Pool) tryGetStream() (*Stream, *ClientSession, error) {
	p.mu.Lock()

	// fix: remove closed Sessions during traversal to prevent unbounded growth
	var active []*ClientSession
	for _, cs := range p.sessions {
		if !cs.IsClosed() {
			active = append(active, cs)
		}
	}
	p.sessions = active

	// find the idle Session with the highest Seq
	var best *ClientSession
	bestIdx := -1
	for i, cs := range p.sessions {
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
			best.close(err)
			return nil, nil, err
		}
		return stream, best, nil
	}
	p.mu.Unlock()

	// no idle Sessions, creating a new one
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

// ReturnSession returns a Session to the idle pool after Stream use.
// If adding this session would exceed maxIdleSession, the oldest idle session is closed.
func (p *Pool) ReturnSession(cs *ClientSession) {
	if cs.IsClosed() {
		return
	}
	cs.SetIdle()
	p.mu.Lock()

	// Enforce hard cap: if over the limit, evict the oldest (lowest seq).
	if p.maxIdleSession > 0 && len(p.sessions) >= p.maxIdleSession {
		p.evictOldestLocked()
	}

	p.sessions = append(p.sessions, cs)
	p.mu.Unlock()
}

// evictOldestLocked closes the idle session with the lowest seq.
// Must be called while holding p.mu.
func (p *Pool) evictOldestLocked() {
	if len(p.sessions) == 0 {
		return
	}
	oldestIdx := 0
	oldestSeq := p.sessions[0].seq
	for i, cs := range p.sessions {
		if cs.seq < oldestSeq {
			oldestSeq = cs.seq
			oldestIdx = i
		}
	}
	victim := p.sessions[oldestIdx]
	p.sessions = append(p.sessions[:oldestIdx], p.sessions[oldestIdx+1:]...)
	log.Printf("[pool] evicting oldest idle session seq=%d (maxIdleSession=%d)", victim.seq, p.maxIdleSession)
	victim.close(nil)
}

// newSession creates a new ClientSession
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

// cleanupLoop periodically cleans up timed-out idle Sessions
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

	// sort by Seq descending (higher Seq = newer)
	sort.Slice(alive, func(i, j int) bool {
		return alive[i].seq > alive[j].seq
	})

	// Enforce max idle cap first (overrides minIdleSession).
	maxKeep := p.maxIdleSession
	if maxKeep <= 0 {
		maxKeep = len(alive) // no cap
	}
	if maxKeep < p.minIdleSession {
		maxKeep = p.minIdleSession // never keep fewer than min
	}

	var kept []*ClientSession
	for i, cs := range alive {
		// Always keep at least minIdleSession, plus enforce the max cap.
		if i < p.minIdleSession {
			kept = append(kept, cs)
			continue
		}
		if len(kept) >= maxKeep || now.Sub(cs.IdleSince()) > p.idleTimeout {
			log.Printf("[pool] closing idle session seq=%d (idle %v)", cs.seq, now.Sub(cs.IdleSince()))
			cs.close(nil)
		} else {
			kept = append(kept, cs)
		}
	}

	p.sessions = kept
}

// Close shuts down the pool
func (p *Pool) Close() {
	close(p.done)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cs := range p.sessions {
		cs.close(nil)
	}
}