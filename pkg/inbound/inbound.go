package inbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/logger"
	"anygo/pkg/padding"
	"anygo/pkg/session"
	"anygo/pkg/util"

	utls "github.com/refraction-networking/utls"
)

const dialTimeout = 10 * time.Second

// stats: traffic statistics
type stats struct {
	totalConns  atomic.Int64 // total connections
	activeConns atomic.Int64 // active connections
	bytesIn     atomic.Int64 // bytes received from client
	bytesOut    atomic.Int64 // bytes sent to client
}

// Inbound entry node, acts as AnyTLS client
type Inbound struct {
	cfg  *config.MergedConfig
	pool *session.Pool

	scheme   *padding.Scheme
	schemeMu sync.RWMutex

	stats stats

	// semaphore limits max concurrent connections (MaxConns=0 means unlimited)
	sem chan struct{}
}

func New(cfg *config.MergedConfig) *Inbound {
	ib := &Inbound{
		cfg:    cfg,
		scheme: padding.Default(),
	}
	if cfg.MaxConns > 0 {
		ib.sem = make(chan struct{}, cfg.MaxConns)
	}
	return ib
}

func (ib *Inbound) Run() error {
	checkInterval, err := time.ParseDuration(ib.cfg.IdleSessionCheckInterval)
	if err != nil {
		checkInterval = 30 * time.Second
	}
	idleTimeout, err := time.ParseDuration(ib.cfg.IdleSessionTimeout)
	if err != nil {
		idleTimeout = 60 * time.Second
	}

	ib.pool = session.NewPool(
		ib.dialSession,
		checkInterval,
		idleTimeout,
		ib.cfg.MinIdleSession,
		ib.cfg.MaxIdleSession,
	)

	listener, err := net.Listen("tcp", ib.cfg.Listen)
	if err != nil {
		return err
	}

	maxConnsStr := "unlimited"
	if ib.cfg.MaxConns > 0 {
		maxConnsStr = fmt.Sprintf("%d", ib.cfg.MaxConns)
	}
	logger.Info("[inbound] listening %s → %s  sni=%s insecure=%v max_conns=%s",
		ib.cfg.Listen, ib.cfg.Remote, ib.cfg.SNI, ib.cfg.Insecure, maxConnsStr)

	// periodically print traffic statistics
	go ib.statsLoop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("[inbound:%s] accept error: %v", ib.cfg.Listen, err)
			continue
		}

		// connection limit: reject when semaphore is full
		if ib.sem != nil {
			select {
			case ib.sem <- struct{}{}:
				// got slot, continuing
			default:
				logger.Warn("[inbound:%s] connection limit reached %d, rejecting connection from %s",
					ib.cfg.Listen, ib.cfg.MaxConns, conn.RemoteAddr())
				conn.Close()
				continue
			}
		}

		go ib.handleConn(conn)
	}
}

// statsLoop prints traffic stats every 60 seconds
func (ib *Inbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[inbound:%s] stats | total: %d  active: %d  rx: %s  tx: %s",
			ib.cfg.Listen,
			ib.stats.totalConns.Load(),
			ib.stats.activeConns.Load(),
			util.FormatBytes(ib.stats.bytesIn.Load()),
			util.FormatBytes(ib.stats.bytesOut.Load()),
		)
	}
}

func (ib *Inbound) getScheme() *padding.Scheme {
	ib.schemeMu.RLock()
	defer ib.schemeMu.RUnlock()
	return ib.scheme
}

func (ib *Inbound) updateScheme(scheme *padding.Scheme) {
	ib.schemeMu.Lock()
	ib.scheme = scheme
	ib.schemeMu.Unlock()
	logger.Info("[inbound:%s] padding scheme synced, md5=%s", ib.cfg.Listen, scheme.MD5())
}

func (ib *Inbound) dialSession() (*session.ClientSession, error) {
	conn, err := ib.dialTLS()
	if err != nil {
		return nil, err
	}

	scheme := ib.getScheme()

	if err := ib.sendAuth(conn, scheme); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth failed: %w", err)
	}

	cs, err := session.NewClientSession(conn, ib.cfg.Password, scheme, ib.updateScheme)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("session handshake failed: %w", err)
	}
	return cs, nil
}

func (ib *Inbound) dialTLS() (net.Conn, error) {
	tcpConn, err := net.DialTimeout("tcp", ib.cfg.Remote, dialTimeout)
	if err != nil {
		return nil, err
	}

	if ib.cfg.SNI != "" {
		tlsConfig := &utls.Config{
			ServerName:         ib.cfg.SNI,
			InsecureSkipVerify: ib.cfg.Insecure,
		}
		uConn := utls.UClient(tcpConn, tlsConfig, utls.HelloChrome_Auto)
		if err := uConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, err
		}
		return uConn, nil
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (ib *Inbound) sendAuth(conn net.Conn, scheme *padding.Scheme) error {
	h := sha256.Sum256([]byte(ib.cfg.Password))
	padding0 := padding.RandBytes(scheme.Padding0Size())
	err := frame.WriteAuth(conn, h[:], padding0)
	padding.ReleaseRandBytes(padding0)
	return err
}

func (ib *Inbound) handleConn(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		ib.stats.activeConns.Add(-1)
		if ib.sem != nil {
			<-ib.sem
		}
	}()

	ib.stats.totalConns.Add(1)
	ib.stats.activeConns.Add(1)

	stream, cs, err := ib.pool.GetStream()
	if err != nil {
		logger.Error("[inbound:%s] get stream failed: %v", ib.cfg.Listen, err)
		return
	}
	defer func() {
		stream.Close()
		ib.pool.ReturnSession(cs)
	}()

	logger.Debug("[inbound:%s] stream #%d established", ib.cfg.Listen, stream.ID())

	// bidirectional relay with stats
	in, out := util.RelayWithStats(clientConn, stream)
	ib.stats.bytesIn.Add(in)
	ib.stats.bytesOut.Add(out)

	logger.Debug("[inbound:%s] stream #%d ended  rx%s  tx%s",
		ib.cfg.Listen, stream.ID(), util.FormatBytes(in), util.FormatBytes(out))
}

