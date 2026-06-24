package outbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/logger"
	"anygo/pkg/padding"
	"anygo/pkg/session"
	"anygo/pkg/util"
)

// stats: traffic statistics
type stats struct {
	totalConns  atomic.Int64
	activeConns atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

// Outbound exit node, acts as AnyTLS server
type Outbound struct {
	cfg    *config.MergedConfig
	scheme *padding.Scheme
	stats  stats

	// semaphore limits max concurrent connections
	sem chan struct{}
}

func New(cfg *config.MergedConfig) *Outbound {
	scheme := padding.Default()
	if cfg.PaddingScheme != "" {
		s, err := padding.Parse(cfg.PaddingScheme)
		if err != nil {
			logger.Warn("[outbound] invalid paddingScheme, using default: %v", err)
		} else {
			scheme = s
		}
	}
	ob := &Outbound{cfg: cfg, scheme: scheme}
	if cfg.MaxConns > 0 {
		ob.sem = make(chan struct{}, cfg.MaxConns)
	}
	return ob
}

func (ob *Outbound) Run() error {
	tlsConfig, err := ob.buildTLSConfig()
	if err != nil {
		return err
	}

	listener, err := tls.Listen("tcp", ob.cfg.Listen, tlsConfig)
	if err != nil {
		return err
	}

	maxConnsStr := "unlimited"
	if ob.cfg.MaxConns > 0 {
		maxConnsStr = fmt.Sprintf("%d", ob.cfg.MaxConns)
	}
	logger.Info("[outbound] listening %s → %s  padding_md5=%s  max_conns=%s",
		ob.cfg.Listen, ob.cfg.Remote, ob.scheme.MD5(), maxConnsStr)

	// periodically print traffic statistics
	go ob.statsLoop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("[outbound:%s] accept error: %v", ob.cfg.Listen, err)
			continue
		}

		// connection limit
		if ob.sem != nil {
			select {
			case ob.sem <- struct{}{}:
			default:
				logger.Warn("[outbound:%s] connection limit reached %d, rejecting connection from %s",
					ob.cfg.Listen, ob.cfg.MaxConns, conn.RemoteAddr())
				conn.Close()
				continue
			}
		}

		go ob.handleConn(conn)
	}
}

func (ob *Outbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[outbound:%s] stats | total: %d  active: %d  rx: %s  tx: %s",
			ob.cfg.Listen,
			ob.stats.totalConns.Load(),
			ob.stats.activeConns.Load(),
			util.FormatBytes(ob.stats.bytesIn.Load()),
			util.FormatBytes(ob.stats.bytesOut.Load()),
		)
	}
}

func (ob *Outbound) buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (ob *Outbound) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		ob.stats.activeConns.Add(-1)
		if ob.sem != nil {
			<-ob.sem
		}
	}()

	ob.stats.totalConns.Add(1)
	ob.stats.activeConns.Add(1)

	if err := ob.authenticate(conn); err != nil {
		logger.Warn("[outbound:%s] auth failed from %s: %v, falling back to HTTP",
			ob.cfg.Listen, conn.RemoteAddr(), err)
		ob.fallbackHTTP(conn)
		return
	}
	logger.Debug("[outbound:%s] auth succeeded: %s", ob.cfg.Listen, conn.RemoteAddr())

	ss, err := session.NewServerSession(conn, ob.scheme)
	if err != nil {
		logger.Error("[outbound:%s] session handshake failed: %v", ob.cfg.Listen, err)
		return
	}

	for {
		stream, err := ss.AcceptStream()
		if err != nil {
			return
		}
		go ob.handleStream(stream)
	}
}

func (ob *Outbound) authenticate(conn net.Conn) error {
	passwordHash, _, err := frame.ReadAuth(conn)
	if err != nil {
		return fmt.Errorf("failed to read auth packet: %w", err)
	}
	expected := sha256.Sum256([]byte(ob.cfg.Password))
	if !util.EqualBytes(passwordHash, expected[:]) {
		return fmt.Errorf("wrong password")
	}
	return nil
}

func (ob *Outbound) handleStream(stream *session.Stream) {
	defer stream.Close()

	targetConn, err := net.Dial("tcp", ob.cfg.Remote)
	if err != nil {
		logger.Error("[outbound:%s] failed to connect to target %s: %v", ob.cfg.Listen, ob.cfg.Remote, err)
		return
	}
	defer targetConn.Close()

	logger.Debug("[outbound:%s] stream #%d → %s", ob.cfg.Listen, stream.ID(), ob.cfg.Remote)

	in, out := util.RelayWithStats(stream, targetConn)
	ob.stats.bytesIn.Add(in)
	ob.stats.bytesOut.Add(out)

	logger.Debug("[outbound:%s] stream #%d ended  rx%s  tx%s",
		ob.cfg.Listen, stream.ID(), util.FormatBytes(in), util.FormatBytes(out))
}

// fallbackHTTP returns a fake nginx HTTP response on auth failure to resist active probing
func (ob *Outbound) fallbackHTTP(conn net.Conn) {
	body := "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n" +
		"<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>\n" +
		"</head>\n<body>\n<h1>Welcome to nginx!</h1>\n" +
		"<p>If you see this page, the nginx web server is successfully installed and working.</p>\n" +
		"<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"

	now := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	resp := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Date: " + now + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		body

	conn.Write([]byte(resp))
}
