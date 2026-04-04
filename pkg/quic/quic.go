package quic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"anygo/config"

	quicgo "github.com/quic-go/quic-go"
)

const (
	udpDialTimeout = 10 * time.Second
	udpIdleTimeout = 60 * time.Second
	udpReadTimeout = 10 * time.Second
	udpBufSize     = 65535
	quicALPN       = "anygo-udp"
)

// ─────────────────────────────────────────────────
// 公用帧读写：[2字节长度 BE][数据]
// ─────────────────────────────────────────────────

func writeFrame(w io.Writer, data []byte) error {
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	copy(buf[2:], data)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(lenBuf)
	if size == 0 {
		return nil, nil
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
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

// ─────────────────────────────────────────────────
// Inbound：境内UDP入口，QUIC客户端
// ─────────────────────────────────────────────────

type Inbound struct {
	cfg    *config.MergedConfig
	conn   *quicgo.Conn // v0.53+ 使用 *Conn 而非 Connection 接口
	connMu sync.Mutex
}

func NewInbound(cfg *config.MergedConfig) *Inbound {
	return &Inbound{cfg: cfg}
}

func (ib *Inbound) Run() error {
	addr, err := net.ResolveUDPAddr("udp", ib.cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("[quic-inbound] 监听 %s → %s", ib.cfg.Listen, ib.cfg.Remote)

	buf := make([]byte, udpBufSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[quic-inbound:%s] read error: %v", ib.cfg.Listen, err)
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go ib.handlePacket(conn, clientAddr, data)
	}
}

// getQUICConn 获取或重建QUIC连接
func (ib *Inbound) getQUICConn() (*quicgo.Conn, error) {
	ib.connMu.Lock()
	defer ib.connMu.Unlock()

	if ib.conn != nil {
		select {
		case <-ib.conn.Context().Done():
			ib.conn = nil
		default:
			return ib.conn, nil
		}
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: ib.cfg.Insecure,
		ServerName:         ib.cfg.SNI,
		NextProtos:         []string{quicALPN},
	}

	ctx, cancel := context.WithTimeout(context.Background(), udpDialTimeout)
	defer cancel()

	qconn, err := quicgo.DialAddr(ctx, ib.cfg.Remote, tlsCfg, &quicgo.Config{
		MaxIdleTimeout:  udpIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	// 认证：第一个stream发送sha256(password)
	authCtx, authCancel := context.WithTimeout(context.Background(), udpDialTimeout)
	defer authCancel()

	authStream, err := qconn.OpenStreamSync(authCtx)
	if err != nil {
		qconn.CloseWithError(0, "auth stream failed")
		return nil, err
	}
	h := sha256.Sum256([]byte(ib.cfg.Password))
	if _, err := authStream.Write(h[:]); err != nil {
		qconn.CloseWithError(0, "auth write failed")
		return nil, err
	}
	authStream.Close()

	ib.conn = qconn
	log.Printf("[quic-inbound] QUIC连接建立 → %s", ib.cfg.Remote)
	return qconn, nil
}

// handlePacket 每个UDP包对应一个QUIC stream
func (ib *Inbound) handlePacket(localConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	qconn, err := ib.getQUICConn()
	if err != nil {
		log.Printf("[quic-inbound] 获取QUIC连接失败: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), udpDialTimeout)
	defer cancel()

	// v0.53+ OpenStreamSync 返回 *quic.Stream
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		log.Printf("[quic-inbound] 打开stream失败: %v", err)
		ib.connMu.Lock()
		ib.conn = nil
		ib.connMu.Unlock()
		return
	}
	defer stream.Close()

	// 发送UDP数据
	if err := writeFrame(stream, data); err != nil {
		return
	}
	stream.Close()

	// 读取响应
	stream.SetReadDeadline(time.Now().Add(udpReadTimeout))
	resp, err := readFrame(stream)
	if err != nil || len(resp) == 0 {
		return
	}

	localConn.WriteToUDP(resp, clientAddr)
}

// ─────────────────────────────────────────────────
// Outbound：境外UDP出口，QUIC服务端
// ─────────────────────────────────────────────────

type Outbound struct {
	cfg *config.MergedConfig
}

func NewOutbound(cfg *config.MergedConfig) *Outbound {
	return &Outbound{cfg: cfg}
}

func (ob *Outbound) Run() error {
	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}

	listener, err := quicgo.ListenAddr(ob.cfg.Listen, tlsCfg, &quicgo.Config{
		MaxIdleTimeout:  udpIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("[quic-outbound] QUIC监听 %s → %s", ob.cfg.Listen, ob.cfg.Remote)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("[quic-outbound] accept error: %v", err)
			continue
		}
		go ob.handleConn(conn)
	}
}

func (ob *Outbound) handleConn(conn *quicgo.Conn) {
	defer conn.CloseWithError(0, "done")

	// 第一个stream是认证
	authStream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	token := make([]byte, 32)
	if _, err := io.ReadFull(authStream, token); err != nil {
		conn.CloseWithError(1, "auth read failed")
		return
	}
	authStream.Close()

	expected := sha256.Sum256([]byte(ob.cfg.Password))
	if !equalBytes(token, expected[:]) {
		log.Printf("[quic-outbound] 认证失败 from %s", conn.RemoteAddr())
		conn.CloseWithError(1, "auth failed")
		return
	}
	log.Printf("[quic-outbound] QUIC认证成功: %s", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go ob.handleStream(stream)
	}
}

func (ob *Outbound) handleStream(stream *quicgo.Stream) {
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(udpReadTimeout))
	data, err := readFrame(stream)
	if err != nil || len(data) == 0 {
		return
	}

	targetAddr, err := net.ResolveUDPAddr("udp", ob.cfg.Remote)
	if err != nil {
		log.Printf("[quic-outbound] 解析目标地址失败: %v", err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("[quic-outbound] 连接目标UDP失败: %v", err)
		return
	}
	defer udpConn.Close()

	if _, err := udpConn.Write(data); err != nil {
		return
	}

	udpConn.SetReadDeadline(time.Now().Add(udpReadTimeout))
	buf := make([]byte, udpBufSize)
	n, err := udpConn.Read(buf)
	if err != nil {
		return
	}

	writeFrame(stream, buf[:n])
	log.Printf("[quic-outbound] stream#%d %d→%d bytes", stream.StreamID(), len(data), n)
}