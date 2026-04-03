package outbound

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

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
	// 如果配置了自定义paddingScheme，使用自定义的
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
	log.Printf("[outbound] 目标服务器: %s", ob.cfg.Remote)
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

// buildTLSConfig 构建TLS配置，支持自签证书
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

// handleConn 处理一个来自inbound的连接
func (ob *Outbound) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. 认证
	if err := ob.authenticate(conn); err != nil {
		log.Printf("[outbound] 认证失败 from %s: %v，fallback HTTP", conn.RemoteAddr(), err)
		ob.fallbackHTTP(conn)
		return
	}
	log.Printf("[outbound] 认证成功: %s", conn.RemoteAddr())

	// 2. 建立ServerSession（内部等待cmdSettings并完成握手）
	ss, err := session.NewServerSession(conn, ob.scheme)
	if err != nil {
		log.Printf("[outbound] session握手失败: %v", err)
		return
	}

	// 3. 循环接受Stream
	for {
		stream, err := ss.AcceptStream()
		if err != nil {
			return
		}
		go ob.handleStream(stream)
	}
}

// authenticate 验证认证包
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

// handleStream 处理一个Stream：读目标地址，连接目标，双向中继
func (ob *Outbound) handleStream(stream *session.Stream) {
	defer stream.Close()

	// 读目标地址（2字节长度前缀 + 地址字符串）
	target, err := readSocksAddr(stream)
	if err != nil {
		log.Printf("[outbound] 读取目标地址失败: %v", err)
		return
	}

	// 连接目标服务器
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[outbound] 连接目标 %s 失败: %v", target, err)
		return
	}
	defer targetConn.Close()

	log.Printf("[outbound] stream #%d → %s", stream.ID(), target)

	// 双向中继
	relay(stream, targetConn)
}

// readSocksAddr 读取目标地址（2字节长度前缀 + 地址字符串）
func readSocksAddr(r io.Reader) (string, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", err
	}
	addrLen := binary.BigEndian.Uint16(lenBuf)
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", err
	}
	return string(addrBuf), nil
}

// fallbackHTTP 认证失败时返回正常HTTP响应（防主动探测）
func (ob *Outbound) fallbackHTTP(conn net.Conn) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(nil),
	}
	_ = resp
	// 简单返回一个正常页面
	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!"))
}

// relay 双向转发
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
