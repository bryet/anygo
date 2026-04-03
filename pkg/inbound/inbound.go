package inbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/padding"
	"anygo/pkg/session"

	utls "github.com/refraction-networking/utls"
)

const (
	reconnectBaseDelay = 1 * time.Second
	reconnectMaxDelay  = 30 * time.Second
	dialTimeout        = 10 * time.Second
)

// Inbound 境内入口节点，扮演AnyTLS客户端角色
type Inbound struct {
	cfg    *config.Config
	scheme *padding.Scheme
	pool   *session.Pool
}

func New(cfg *config.Config) *Inbound {
	return &Inbound{
		cfg:    cfg,
		scheme: padding.Default(),
	}
}

func (ib *Inbound) Run() error {
	ib.pool = session.NewPool(
		ib.dialSession,
		30*time.Second,
		60*time.Second,
		2,
	)

	listener, err := net.Listen("tcp", ib.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("[inbound] 监听 %s", ib.cfg.Listen)
	log.Printf("[inbound] 出口服务器: %s  SNI: %s  insecure: %v", ib.cfg.Remote, ib.cfg.SNI, ib.cfg.Insecure)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[inbound] accept error:", err)
			continue
		}
		go ib.handleConn(conn)
	}
}

func (ib *Inbound) dialSession() (*session.ClientSession, error) {
	conn, err := ib.dialTLS()
	if err != nil {
		return nil, err
	}
	if err := ib.sendAuth(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth failed: %w", err)
	}
	cs, err := session.NewClientSession(conn, ib.cfg.Password, ib.scheme)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("session handshake failed: %w", err)
	}
	return cs, nil
}

// dialTLS 建立TLS连接：
//   - 有 SNI：始终使用 uTLS 伪装 Chrome 指纹；insecure 控制是否验证证书
//     - insecure=false（真实域名证书）：正常验证
//     - insecure=true（自签证书）：跳过验证
//   - 无 SNI + insecure=true：自签证书且无需指纹伪装，使用标准 Go TLS
func (ib *Inbound) dialTLS() (net.Conn, error) {
	tcpConn, err := net.DialTimeout("tcp", ib.cfg.Remote, dialTimeout)
	if err != nil {
		return nil, err
	}

	if ib.cfg.SNI != "" {
		// 有 SNI：使用 uTLS 伪装 Chrome 指纹
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

	// 无 SNI：标准 Go TLS，跳过证书验证
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (ib *Inbound) sendAuth(conn net.Conn) error {
	h := sha256.Sum256([]byte(ib.cfg.Password))
	padding0 := padding.RandBytes(ib.scheme.Padding0Size())
	return frame.WriteAuth(conn, h[:], padding0)
}

func (ib *Inbound) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	stream, cs, err := ib.pool.GetStream()
	if err != nil {
		log.Printf("[inbound] 获取stream失败: %v", err)
		return
	}
	defer func() {
		stream.Close()
		ib.pool.ReturnSession(cs)
	}()

	log.Printf("[inbound] stream #%d 已建立", stream.ID())
	relay(clientConn, stream)
}

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
}
