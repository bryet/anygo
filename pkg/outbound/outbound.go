package outbound

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
)

// Outbound 境外出口节点，扮演AnyTLS服务端角色
type Outbound struct {
	cfg    *config.MergedConfig
	scheme *padding.Scheme
}

func New(cfg *config.MergedConfig) *Outbound {
	scheme := padding.Default()
	if cfg.PaddingScheme != "" {
		s, err := padding.Parse(cfg.PaddingScheme)
		if err != nil {
			log.Printf("[outbound] 无效的paddingScheme，使用默认值: %v", err)
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

	log.Printf("[outbound] 监听 %s → %s  padding_md5=%s", ob.cfg.Listen, ob.cfg.Remote, ob.scheme.MD5())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[outbound:%s] accept error: %v", ob.cfg.Listen, err)
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
		log.Printf("[outbound:%s] 认证失败 from %s: %v，fallback HTTP", ob.cfg.Listen, conn.RemoteAddr(), err)
		ob.fallbackHTTP(conn)
		return
	}
	log.Printf("[outbound:%s] 认证成功: %s", ob.cfg.Listen, conn.RemoteAddr())

	ss, err := session.NewServerSession(conn, ob.scheme)
	if err != nil {
		log.Printf("[outbound:%s] session握手失败: %v", ob.cfg.Listen, err)
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
		log.Printf("[outbound:%s] 连接目标 %s 失败: %v", ob.cfg.Listen, ob.cfg.Remote, err)
		return
	}
	defer targetConn.Close()

	log.Printf("[outbound:%s] stream #%d → %s", ob.cfg.Listen, stream.ID(), ob.cfg.Remote)
	relay(stream, targetConn)
}

// fallbackHTTP 认证失败时返回仿 nginx 的 HTTP 响应，防止主动探测识别
func (ob *Outbound) fallbackHTTP(conn net.Conn) {
	now := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	resp := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Date: " + now + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: 615\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n" +
		"<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>\n" +
		"</head>\n<body>\n<h1>Welcome to nginx!</h1>\n" +
		"<p>If you see this page, the nginx web server is successfully installed and working.</p>\n" +
		"<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"
	conn.Write([]byte(resp))
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