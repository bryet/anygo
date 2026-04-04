package quic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
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

// dialCall 用于实现 singleflight：同一时刻只允许一个 goroutine 重建连接
type dialCall struct {
	wg  sync.WaitGroup
	val *quicgo.Conn
	err error
}

type Inbound struct {
	cfg    *config.MergedConfig
	conn   *quicgo.Conn
	connMu sync.RWMutex

	// singleflight：重建连接期间，后续请求等待同一次结果
	dialMu  sync.Mutex
	dialing *dialCall
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
// 快路径：RWMutex 读锁，连接有效直接返回，无阻塞
// 慢路径：singleflight 保证同一时刻只有一个 goroutine 做重建，
//
//	其余 goroutine 等待同一次重建结果，不会全部串行等锁
func (ib *Inbound) getQUICConn() (*quicgo.Conn, error) {
	// 快路径
	ib.connMu.RLock()
	conn := ib.conn
	ib.connMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
			// 连接失效，走慢路径
		default:
			return conn, nil
		}
	}

	// 慢路径：singleflight
	ib.dialMu.Lock()
	if ib.dialing != nil {
		// 已有 goroutine 在重建，等它完成
		call := ib.dialing
		ib.dialMu.Unlock()
		call.wg.Wait()
		return call.val, call.err
	}
	call := &dialCall{}
	call.wg.Add(1)
	ib.dialing = call
	ib.dialMu.Unlock()

	call.val, call.err = ib.dialQUIC()
	call.wg.Done()

	ib.dialMu.Lock()
	ib.dialing = nil
	ib.dialMu.Unlock()

	return call.val, call.err
}

// dialQUIC 建立新的QUIC连接并完成认证，成功后写入 ib.conn
func (ib *Inbound) dialQUIC() (*quicgo.Conn, error) {
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

	ib.connMu.Lock()
	ib.conn = qconn
	ib.connMu.Unlock()

	log.Printf("[quic-inbound] QUIC连接建立 → %s", ib.cfg.Remote)
	return qconn, nil
}

// handlePacket 每个UDP包对应一个QUIC stream，一问一答后由defer关闭
func (ib *Inbound) handlePacket(localConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	qconn, err := ib.getQUICConn()
	if err != nil {
		log.Printf("[quic-inbound] 获取QUIC连接失败: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), udpDialTimeout)
	defer cancel()

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		log.Printf("[quic-inbound] 打开stream失败: %v", err)
		ib.connMu.Lock()
		ib.conn = nil
		ib.connMu.Unlock()
		return
	}
	defer stream.Close()

	if err := writeFrame(stream, data); err != nil {
		log.Printf("[quic-inbound] 发送请求失败: %v", err)
		return
	}

	stream.SetReadDeadline(time.Now().Add(udpReadTimeout))
	resp, err := readFrame(stream)
	if err != nil {
		if err != io.EOF {
			log.Printf("[quic-inbound] 读取响应失败: %v", err)
		}
		return
	}
	if len(resp) == 0 {
		return
	}

	localConn.WriteToUDP(resp, clientAddr)
}

// ─────────────────────────────────────────────────
// Outbound：境外UDP出口，QUIC服务端
// ─────────────────────────────────────────────────

type Outbound struct {
	cfg     *config.MergedConfig
	udpConn *net.UDPConn // 复用的共享 UDPConn，避免每个 stream 新建 socket
	udpMu   sync.Mutex
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

	// 预先建立共享 UDPConn
	if err := ob.initUDPConn(); err != nil {
		return err
	}
	defer ob.udpConn.Close()

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

func (ob *Outbound) initUDPConn() error {
	targetAddr, err := net.ResolveUDPAddr("udp", ob.cfg.Remote)
	if err != nil {
		return fmt.Errorf("解析目标地址失败: %w", err)
	}
	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return fmt.Errorf("创建UDP连接失败: %w", err)
	}
	ob.udpConn = udpConn
	return nil
}

func (ob *Outbound) handleConn(conn *quicgo.Conn) {
	defer conn.CloseWithError(0, "done")

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

// handleStream 复用共享 UDPConn 收发
// 注意：互斥锁保证同一时刻只有一个 stream 在收发，保证请求和响应的对应关系
// 若目标服务是有状态的多路复用 UDP（如 QUIC），需要改为每个 stream 独立 UDPConn
func (ob *Outbound) handleStream(stream *quicgo.Stream) {
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(udpReadTimeout))
	data, err := readFrame(stream)
	if err != nil || len(data) == 0 {
		return
	}

	ob.udpMu.Lock()
	_, err = ob.udpConn.Write(data)
	if err != nil {
		ob.udpMu.Unlock()
		log.Printf("[quic-outbound] UDP发送失败: %v", err)
		return
	}
	ob.udpConn.SetReadDeadline(time.Now().Add(udpReadTimeout))
	buf := make([]byte, udpBufSize)
	n, err := ob.udpConn.Read(buf)
	ob.udpMu.Unlock()

	if err != nil {
		return
	}

	if err := writeFrame(stream, buf[:n]); err != nil {
		return
	}
	log.Printf("[quic-outbound] stream#%d %d→%d bytes", stream.StreamID(), len(data), n)
}