package outbound

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"anygo/config"
	"anygo/pkg/frame"
	"anygo/pkg/padding"
	"anygo/pkg/session"
)

// Outbound 境外出口节点，扮演AnyTLS服务端角色
type Outbound struct {
	cfg    *config.Config
	scheme *padding.Scheme
}

func New(cfg *config.Config) *Outbound {
	scheme := padding.Default()
	if cfg.PaddingScheme != "" {
		s, err := padding.Parse(cfg.PaddingScheme)
		if err != nil {
			log.Printf("[outbound] 无效的paddingScheme配置，使用默认值: %v", err)
		} else {
			scheme = s
		}
	}
	return &Outbound{cfg: cfg, scheme: scheme}
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

	log.Printf("[outbound] 监听 %s", ob.cfg.Listen)
	log.Printf("[outbound] SNI: %s", ob.cfg.SNI)
	log.Printf("[outbound] 转发目标: %s", ob.cfg.Remote)
	log.Printf("[outbound] PaddingScheme md5: %s", ob.scheme.MD5())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[outbound] accept error:", err)
			continue
		}
		go ob.handleConn(conn)
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
	defer conn.Close()

	if err := ob.authenticate(conn); err != nil {
		log.Printf("[outbound] 认证失败 from %s: %v，fallback HTTP", conn.RemoteAddr(), err)
		ob.fallbackHTTP(conn)
		return
	}
	log.Printf("[outbound] 认证成功: %s", conn.RemoteAddr())

	ss, err := session.NewServerSession(conn, ob.scheme)
	if err != nil {
		log.Printf("[outbound] session握手失败: %v", err)
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
		log.Printf("[outbound] 连接目标 %s 失败: %v", ob.cfg.Remote, err)
		return
	}
	defer targetConn.Close()

	log.Printf("[outbound] stream #%d → %s", stream.ID(), ob.cfg.Remote)
	relay(stream, targetConn)
}

func (ob *Outbound) fallbackHTTP(conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"))
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
