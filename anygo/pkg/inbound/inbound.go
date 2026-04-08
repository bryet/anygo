package inbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/logger"
	"anygo/pkg/padding"
	"anygo/pkg/session"

	utls "github.com/refraction-networking/utls"
)

const dialTimeout = 10 * time.Second

// stats 流量统计
type stats struct {
	totalConns  atomic.Int64 // 累计连接数
	activeConns atomic.Int64 // 当前活跃连接数
	bytesIn     atomic.Int64 // 从客户端收到的字节数
	bytesOut    atomic.Int64 // 发送给客户端的字节数
}

// Inbound 境内入口节点，扮演AnyTLS客户端角色
type Inbound struct {
	cfg  *config.MergedConfig
	pool *session.Pool

	scheme   *padding.Scheme
	schemeMu sync.RWMutex

	stats stats

	// semaphore 限制最大并发连接数（MaxConns=0 表示不限制）
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
	)

	listener, err := net.Listen("tcp", ib.cfg.Listen)
	if err != nil {
		return err
	}

	maxConnsStr := "unlimited"
	if ib.cfg.MaxConns > 0 {
		maxConnsStr = fmt.Sprintf("%d", ib.cfg.MaxConns)
	}
	logger.Info("[inbound] 监听 %s → %s  sni=%s insecure=%v max_conns=%s",
		ib.cfg.Listen, ib.cfg.Remote, ib.cfg.SNI, ib.cfg.Insecure, maxConnsStr)

	// 定期打印流量统计
	go ib.statsLoop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("[inbound:%s] accept error: %v", ib.cfg.Listen, err)
			continue
		}

		// 连接数限制：semaphore 满时直接拒绝
		if ib.sem != nil {
			select {
			case ib.sem <- struct{}{}:
				// 获取到 slot，继续
			default:
				logger.Warn("[inbound:%s] 连接数已达上限 %d，拒绝连接 from %s",
					ib.cfg.Listen, ib.cfg.MaxConns, conn.RemoteAddr())
				conn.Close()
				continue
			}
		}

		go ib.handleConn(conn)
	}
}

// statsLoop 每60秒打印一次流量统计
func (ib *Inbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[inbound:%s] 统计 | 累计连接: %d  活跃: %d  收: %s  发: %s",
			ib.cfg.Listen,
			ib.stats.totalConns.Load(),
			ib.stats.activeConns.Load(),
			formatBytes(ib.stats.bytesIn.Load()),
			formatBytes(ib.stats.bytesOut.Load()),
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
	logger.Info("[inbound:%s] padding scheme 已同步更新 md5=%s", ib.cfg.Listen, scheme.MD5())
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
	return frame.WriteAuth(conn, h[:], padding0)
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
		logger.Error("[inbound:%s] 获取stream失败: %v", ib.cfg.Listen, err)
		return
	}
	defer func() {
		stream.Close()
		ib.pool.ReturnSession(cs)
	}()

	logger.Debug("[inbound:%s] stream #%d 已建立", ib.cfg.Listen, stream.ID())

	// 统计流量的双向中继
	in, out := relayWithStats(clientConn, stream)
	ib.stats.bytesIn.Add(in)
	ib.stats.bytesOut.Add(out)

	logger.Debug("[inbound:%s] stream #%d 结束 收%s 发%s",
		ib.cfg.Listen, stream.ID(), formatBytes(in), formatBytes(out))
}

// relayWithStats 双向转发，返回（从a收到的字节数，发给a的字节数）
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

// formatBytes 格式化字节数为人类可读格式
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