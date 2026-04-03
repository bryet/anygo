package inbound

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"config"
	"pkg/tunnel"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

const (
	reconnectBaseDelay = 1 * time.Second
	reconnectMaxDelay  = 30 * time.Second
	dialTimeout        = 10 * time.Second
)

// Inbound 境内入口节点
// 职责：接收客户端TCP连接 → 通过AnyTLS加密隧道转发到境外出口
type Inbound struct {
	cfg     *config.Config
	session *smux.Session
	mu      sync.Mutex

	// 断线重连控制
	reconnecting bool
	sessionReady chan struct{} // session就绪信号
}

func New(cfg *config.Config) *Inbound {
	return &Inbound{
		cfg:          cfg,
		sessionReady: make(chan struct{}),
	}
}

func (ib *Inbound) Run() error {
	listener, err := net.Listen("tcp", ib.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("[inbound] 监听 %s", ib.cfg.Listen)
	log.Printf("[inbound] 出口服务器: %s  SNI: %s", ib.cfg.Remote, ib.cfg.SNI)

	// 启动时主动建立session
	go ib.maintainSession()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[inbound] accept error:", err)
			continue
		}
		go ib.handleConn(conn)
	}
}

// maintainSession 持续维护到境外服务器的session，断线自动重连
func (ib *Inbound) maintainSession() {
	delay := reconnectBaseDelay

	for {
		log.Printf("[inbound] 正在连接出口服务器 %s ...", ib.cfg.Remote)

		session, err := ib.dial()
		if err != nil {
			log.Printf("[inbound] 连接失败: %v，%v 后重试", err, delay)
			time.Sleep(delay)
			delay = min(delay*2, reconnectMaxDelay)
			continue
		}

		// 连接成功，重置延迟
		delay = reconnectBaseDelay
		log.Println("[inbound] 隧道连接成功")

		ib.mu.Lock()
		ib.session = session
		// 通知等待中的goroutine session已就绪
		close(ib.sessionReady)
		ib.sessionReady = make(chan struct{})
		ib.mu.Unlock()

		// 等待session关闭
		ib.waitSessionClosed(session)
		log.Println("[inbound] 隧道断开，准备重连...")
	}
}

// dial 建立TLS连接并完成认证，返回smux session
func (ib *Inbound) dial() (*smux.Session, error) {
	// 1. TCP拨号
	tcpConn, err := net.DialTimeout("tcp", ib.cfg.Remote, dialTimeout)
	if err != nil {
		return nil, err
	}

	// 2. uTLS握手，伪装成Chrome
	tlsConfig := &utls.Config{
		ServerName:         ib.cfg.SNI,
		InsecureSkipVerify: false,
	}
	uConn := utls.UClient(tcpConn, tlsConfig, utls.HelloChrome_Auto)
	if err := uConn.HandshakeContext(nil); err != nil {
		tcpConn.Close()
		return nil, err
	}

	// 3. 发送认证token
	token := tunnel.AuthToken(ib.cfg.Password)
	if _, err := uConn.Write(token); err != nil {
		uConn.Close()
		return nil, err
	}

	// 4. 建立smux客户端session（内含padding层）
	session, err := tunnel.NewClientSession(uConn, ib.cfg.Padding)
	if err != nil {
		uConn.Close()
		return nil, err
	}

	return session, nil
}

// waitSessionClosed 阻塞直到session关闭
func (ib *Inbound) waitSessionClosed(session *smux.Session) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if session.IsClosed() {
			return
		}
	}
}

// getSession 获取当前有效的session，若未就绪则等待
func (ib *Inbound) getSession() (*smux.Session, chan struct{}) {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	return ib.session, ib.sessionReady
}

// handleConn 处理一个客户端连接
func (ib *Inbound) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 获取session，若未就绪最多等待10秒
	session, ready := ib.getSession()
	if session == nil || session.IsClosed() {
		select {
		case <-ready:
			session, _ = ib.getSession()
		case <-time.After(10 * time.Second):
			log.Println("[inbound] 等待隧道超时，丢弃连接")
			return
		}
	}

	// 在session上开一个stream
	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("[inbound] 开启stream失败: %v", err)
		return
	}
	defer stream.Close()

	log.Printf("[inbound] stream #%d 已建立", stream.ID())

	// 双向转发
	relay(clientConn, stream)
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

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
