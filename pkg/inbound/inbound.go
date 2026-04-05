package inbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/padding"
	"anygo/pkg/session"

	utls "github.com/refraction-networking/utls"
)

const dialTimeout = 10 * time.Second

// Inbound 境内入口节点，扮演AnyTLS客户端角色
type Inbound struct {
	cfg  *config.MergedConfig
	pool *session.Pool

	// 修复：scheme 用读写锁保护，收到服务端 cmdUpdatePaddingScheme 后同步更新
	// 确保后续新建 Session 时使用最新 scheme，不再每次触发服务端重发更新
	scheme   *padding.Scheme
	schemeMu sync.RWMutex
}

func New(cfg *config.MergedConfig) *Inbound {
	return &Inbound{
		cfg:    cfg,
		scheme: padding.Default(),
	}
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
	log.Printf("[inbound] 监听 %s → %s  sni=%s insecure=%v", ib.cfg.Listen, ib.cfg.Remote, ib.cfg.SNI, ib.cfg.Insecure)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[inbound:%s] accept error: %v", ib.cfg.Listen, err)
			continue
		}
		go ib.handleConn(conn)
	}
}

// getScheme 线程安全地获取当前 scheme
func (ib *Inbound) getScheme() *padding.Scheme {
	ib.schemeMu.RLock()
	defer ib.schemeMu.RUnlock()
	return ib.scheme
}

// updateScheme 由 Session 的 onSchemeUpdate 回调触发
func (ib *Inbound) updateScheme(scheme *padding.Scheme) {
	ib.schemeMu.Lock()
	ib.scheme = scheme
	ib.schemeMu.Unlock()
	log.Printf("[inbound:%s] padding scheme 已同步更新 md5=%s", ib.cfg.Listen, scheme.MD5())
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

	// 传入 onSchemeUpdate 回调，Session 收到更新时通知 Inbound 同步
	cs, err := session.NewClientSession(conn, ib.cfg.Password, scheme, ib.updateScheme)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("session handshake failed: %w", err)
	}
	return cs, nil
}

// dialTLS 建立TLS连接：
//   - 有 SNI：使用 uTLS 伪装 Chrome 指纹；insecure 控制是否验证证书
//   - 无 SNI：自签证书，使用标准 Go TLS 跳过验证
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
	defer clientConn.Close()

	stream, cs, err := ib.pool.GetStream()
	if err != nil {
		log.Printf("[inbound:%s] 获取stream失败: %v", ib.cfg.Listen, err)
		return
	}
	defer func() {
		stream.Close()
		ib.pool.ReturnSession(cs)
	}()

	log.Printf("[inbound:%s] stream #%d 已建立", ib.cfg.Listen, stream.ID())
	relay(clientConn, stream)
}

// relay 双向转发，等待两个方向都结束后再返回
func relay(a, b io.ReadWriter) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
	<-done
}