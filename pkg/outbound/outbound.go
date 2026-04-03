package outbound

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"

	"anytls-forward/config"
	"anytls-forward/pkg/tunnel"
	"github.com/xtaci/smux"
)

const (
	dialTimeout      = 10 * time.Second
	maxRetryDelay    = 30 * time.Second
	baseRetryDelay   = 1 * time.Second
)

// Outbound 境外出口节点
// 职责：接受境内节点的TLS连接 → 验证认证 → 解密 → 转发到目标服务器
type Outbound struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Outbound {
	return &Outbound{cfg: cfg}
}

func (ob *Outbound) Run() error {
	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ob.cfg.Listen, tlsConfig)
	if err != nil {
		return err
	}

	log.Printf("[outbound] 监听 %s", ob.cfg.Listen)
	log.Printf("[outbound] 目标服务器: %s", ob.cfg.Remote)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[outbound] accept error:", err)
			continue
		}
		go ob.handleConn(conn)
	}
}

// handleConn 处理一个来自境内节点的连接
func (ob *Outbound) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. 验证认证token（32字节）
	token := make([]byte, 32)
	if _, err := io.ReadFull(conn, token); err != nil {
		log.Printf("[outbound] 读取token失败 from %s: %v", conn.RemoteAddr(), err)
		return
	}

	expected := tunnel.AuthToken(ob.cfg.Password)
	if !bytes.Equal(token, expected) {
		log.Printf("[outbound] 认证失败 from %s", conn.RemoteAddr())
		return
	}

	log.Printf("[outbound] 认证成功: %s", conn.RemoteAddr())

	// 2. 建立smux服务端session（内含padding解析层）
	session, err := tunnel.NewServerSession(conn, ob.cfg.Padding)
	if err != nil {
		log.Printf("[outbound] 建立session失败: %v", err)
		return
	}
	defer session.Close()

	// 3. 循环接受stream
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if !session.IsClosed() {
				log.Printf("[outbound] AcceptStream error: %v", err)
			}
			return
		}
		go ob.handleStream(stream)
	}
}

// handleStream 处理一个smux stream，带断线重连转发到目标服务器
func (ob *Outbound) handleStream(stream *smux.Stream) {
	defer stream.Close()

	// 连接目标服务器，失败自动重试
	target, err := ob.dialTargetWithRetry()
	if err != nil {
		log.Printf("[outbound] 无法连接目标服务器 %s: %v", ob.cfg.Remote, err)
		return
	}
	defer target.Close()

	log.Printf("[outbound] stream #%d → %s", stream.ID(), ob.cfg.Remote)

	// 双向转发
	relay(stream, target)
}

// dialTargetWithRetry 带重试的目标服务器拨号
func (ob *Outbound) dialTargetWithRetry() (net.Conn, error) {
	delay := baseRetryDelay
	maxAttempts := 5

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		conn, err := net.DialTimeout("tcp", ob.cfg.Remote, dialTimeout)
		if err == nil {
			return conn, nil
		}

		log.Printf("[outbound] 连接目标服务器失败 (第%d次): %v", attempt, err)
		if attempt < maxAttempts {
			time.Sleep(delay)
			delay = minDuration(delay*2, maxRetryDelay)
		}
	}

	return nil, net.ErrClosed
}

// relay 双向转发两个连接的数据
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

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
