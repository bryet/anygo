package outbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/logger"
	"anygo/pkg/padding"
	"anygo/pkg/session"
)

// stats 流量统计
type stats struct {
	totalConns  atomic.Int64
	activeConns atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

// Outbound 境外出口节点，扮演AnyTLS服务端角色
type Outbound struct {
	cfg    *config.MergedConfig
	scheme *padding.Scheme
	stats  stats

	// semaphore 限制最大并发连接数
	sem chan struct{}
}

func New(cfg *config.MergedConfig) *Outbound {
	scheme := padding.Default()
	if cfg.PaddingScheme != "" {
		s, err := padding.Parse(cfg.PaddingScheme)
		if err != nil {
			logger.Warn("[outbound] 无效的paddingScheme，使用默认值: %v", err)
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
	logger.Info("[outbound] 监听 %s → %s  padding_md5=%s  max_conns=%s",
		ob.cfg.Listen, ob.cfg.Remote, ob.scheme.MD5(), maxConnsStr)

	// 定期打印流量统计
	go ob.statsLoop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("[outbound:%s] accept error: %v", ob.cfg.Listen, err)
			continue
		}

		// 连接数限制
		if ob.sem != nil {
			select {
			case ob.sem <- struct{}{}:
			default:
				logger.Warn("[outbound:%s] 连接数已达上限 %d，拒绝连接 from %s",
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
		logger.Info("[outbound:%s] 统计 | 累计连接: %d  活跃: %d  收: %s  发: %s",
			ob.cfg.Listen,
			ob.stats.totalConns.Load(),
			ob.stats.activeConns.Load(),
			formatBytes(ob.stats.bytesIn.Load()),
			formatBytes(ob.stats.bytesOut.Load()),
		)
	}
}

func (ob *Outbound) buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("加载证书失败: %w", err)
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
		logger.Warn("[outbound:%s] 认证失败 from %s: %v，fallback HTTP",
			ob.cfg.Listen, conn.RemoteAddr(), err)
		ob.fallbackHTTP(conn)
		return
	}
	logger.Debug("[outbound:%s] 认证成功: %s", ob.cfg.Listen, conn.RemoteAddr())

	ss, err := session.NewServerSession(conn, ob.scheme)
	if err != nil {
		logger.Error("[outbound:%s] session握手失败: %v", ob.cfg.Listen, err)
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
		return fmt.Errorf("读取认证包失败: %w", err)
	}
	expected := sha256.Sum256([]byte(ob.cfg.Password))
	if !equalBytes(passwordHash, expected[:]) {
		return fmt.Errorf("密码错误")
	}
	return nil
}

func (ob *Outbound) handleStream(stream *session.Stream) {
	defer stream.Close()

	targetConn, err := net.Dial("tcp", ob.cfg.Remote)
	if err != nil {
		logger.Error("[outbound:%s] 连接目标 %s 失败: %v", ob.cfg.Listen, ob.cfg.Remote, err)
		return
	}
	defer targetConn.Close()

	logger.Debug("[outbound:%s] stream #%d → %s", ob.cfg.Listen, stream.ID(), ob.cfg.Remote)

	in, out := relayWithStats(stream, targetConn)
	ob.stats.bytesIn.Add(in)
	ob.stats.bytesOut.Add(out)

	logger.Debug("[outbound:%s] stream #%d 结束 收%s 发%s",
		ob.cfg.Listen, stream.ID(), formatBytes(in), formatBytes(out))
}

// fallbackHTTP 认证失败时返回仿 nginx 的 HTTP 响应，防止主动探测识别
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

func relayWithStats(a, b io.ReadWriter) (int64, int64) {
	var bytesAtoB, bytesBtoA int64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(b, a)
		bytesAtoB = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(a, b)
		bytesBtoA = n
		done <- struct{}{}
	}()

	<-done
	<-done
	return bytesAtoB, bytesBtoA
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