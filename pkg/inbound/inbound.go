package inbound

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
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
	ib := &Inbound{
		cfg:    cfg,
		scheme: padding.Default(),
	}
	return ib
}

func (ib *Inbound) Run() error {
	// 初始化Session池
	ib.pool = session.NewPool(
		ib.dialSession,
		30*time.Second, // 检查间隔
		60*time.Second, // 空闲超时
		2,              // 最少保留2个空闲Session
	)

	listener, err := net.Listen("tcp", ib.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("[inbound] 监听 %s", ib.cfg.Listen)
	log.Printf("[inbound] 出口服务器: %s  SNI: %s", ib.cfg.Remote, ib.cfg.SNI)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[inbound] accept error:", err)
			continue
		}
		go ib.handleConn(conn)
	}
}

// dialSession 新建一个到出口服务器的ClientSession（注入到Pool）
func (ib *Inbound) dialSession() (*session.ClientSession, error) {
	conn, err := ib.dialTLS()
	if err != nil {
		return nil, err
	}

	// 发送认证包：sha256(password) + padding0
	if err := ib.sendAuth(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth failed: %w", err)
	}

	// 建立ClientSession（内部发送cmdSettings）
	cs, err := session.NewClientSession(conn, ib.cfg.Password, ib.scheme)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("session handshake failed: %w", err)
	}

	return cs, nil
}

// dialTLS 建立TLS连接，使用uTLS伪装Chrome指纹
func (ib *Inbound) dialTLS() (net.Conn, error) {
	tcpConn, err := net.DialTimeout("tcp", ib.cfg.Remote, dialTimeout)
	if err != nil {
		return nil, err
	}

	if ib.cfg.Insecure {
		// 自签证书：跳过验证，使用标准TLS
		tlsConfig := &tls.Config{
			ServerName:         ib.cfg.SNI,
			InsecureSkipVerify: true,
		}
		tlsConn := tls.Client(tcpConn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	// 正式证书：使用uTLS伪装Chrome指纹
	tlsConfig := &utls.Config{
		ServerName:         ib.cfg.SNI,
		InsecureSkipVerify: false,
	}
	uConn := utls.UClient(tcpConn, tlsConfig, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return uConn, nil
}

// sendAuth 发送认证包
func (ib *Inbound) sendAuth(conn net.Conn) error {
	// sha256(password)
	h := sha256.Sum256([]byte(ib.cfg.Password))

	// padding0大小由当前scheme决定
	padding0Size := ib.scheme.Padding0Size()
	padding0 := padding.RandBytes(padding0Size)

	return frame.WriteAuth(conn, h[:], padding0)
}

// handleConn 处理一个客户端TCP连接
func (ib *Inbound) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 从Pool获取Stream（含Session复用逻辑）
	stream, cs, err := ib.pool.GetStream()
	if err != nil {
		log.Printf("[inbound] 获取stream失败: %v", err)
		return
	}
	defer func() {
		stream.Close()
		// Stream用完放回Session池
		ib.pool.ReturnSession(cs)
	}()

	// 发送目标地址（SocksAddr格式）
	// 在anygo中，目标地址就是配置的remote（透明转发）
	target := ib.cfg.Remote
	if err := writeSocksAddr(stream, target); err != nil {
		log.Printf("[inbound] 发送目标地址失败: %v", err)
		return
	}

	log.Printf("[inbound] stream #%d → %s", stream.ID(), target)

	// 双向中继
	relay(clientConn, stream)
}

// writeSocksAddr 向stream写入目标地址（简化版：直接写host:port字符串，用2字节长度前缀）
func writeSocksAddr(w io.Writer, addr string) error {
	b := []byte(addr)
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	copy(buf[2:], b)
	_, err := w.Write(buf)
	return err
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
