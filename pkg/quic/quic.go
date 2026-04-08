package quic

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"anygo/config"
	"anygo/pkg/logger"

	quicgo "github.com/quic-go/quic-go"
)

const (
	udpDialTimeout = 10 * time.Second
	udpIdleTimeout = 60 * time.Second
	udpReadTimeout = 10 * time.Second
	udpBufSize     = 65535
	quicALPN       = "anygo-udp"
)

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

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// ─────────────────────────────────────────────────
// Inbound：境内UDP入口，QUIC客户端
// ─────────────────────────────────────────────────

type dialCall struct {
	wg  sync.WaitGroup
	val *quicgo.Conn
	err error
}

type inboundStats struct {
	totalPkts  atomic.Int64
	activePkts atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

type Inbound struct {
	cfg    *config.MergedConfig
	conn   *quicgo.Conn
	connMu sync.RWMutex

	dialMu  sync.Mutex
	dialing *dialCall

	stats inboundStats
	sem   chan struct{}
}

func NewInbound(cfg *config.MergedConfig) *Inbound {
	ib := &Inbound{cfg: cfg}
	if cfg.MaxConns > 0 {
		ib.sem = make(chan struct{}, cfg.MaxConns)
	}
	return ib
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

	maxConnsStr := "unlimited"
	if ib.cfg.MaxConns > 0 {
		maxConnsStr = fmt.Sprintf("%d", ib.cfg.MaxConns)
	}
	logger.Info("[quic-inbound] 监听 %s → %s  max_conns=%s", ib.cfg.Listen, ib.cfg.Remote, maxConnsStr)

	go ib.statsLoop()

	buf := make([]byte, udpBufSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Error("[quic-inbound:%s] read error: %v", ib.cfg.Listen, err)
			continue
		}

		// UDP 包数量限制
		if ib.sem != nil {
			select {
			case ib.sem <- struct{}{}:
			default:
				logger.Warn("[quic-inbound:%s] 并发包数已达上限 %d，丢弃包", ib.cfg.Listen, ib.cfg.MaxConns)
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go ib.handlePacket(conn, clientAddr, data)
	}
}

func (ib *Inbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[quic-inbound:%s] 统计 | 累计包: %d  并发: %d  收: %s  发: %s",
			ib.cfg.Listen,
			ib.stats.totalPkts.Load(),
			ib.stats.activePkts.Load(),
			formatBytes(ib.stats.bytesIn.Load()),
			formatBytes(ib.stats.bytesOut.Load()),
		)
	}
}

func (ib *Inbound) getQUICConn() (*quicgo.Conn, error) {
	ib.connMu.RLock()
	conn := ib.conn
	ib.connMu.RUnlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
		default:
			return conn, nil
		}
	}

	ib.dialMu.Lock()
	if ib.dialing != nil {
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

	logger.Info("[quic-inbound] QUIC连接建立 → %s", ib.cfg.Remote)
	return qconn, nil
}

func (ib *Inbound) handlePacket(localConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	defer func() {
		ib.stats.activePkts.Add(-1)
		if ib.sem != nil {
			<-ib.sem
		}
	}()

	ib.stats.totalPkts.Add(1)
	ib.stats.activePkts.Add(1)
	ib.stats.bytesIn.Add(int64(len(data)))

	qconn, err := ib.getQUICConn()
	if err != nil {
		logger.Error("[quic-inbound] 获取QUIC连接失败: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), udpDialTimeout)
	defer cancel()

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		logger.Error("[quic-inbound] 打开stream失败: %v", err)
		ib.connMu.Lock()
		ib.conn = nil
		ib.connMu.Unlock()
		return
	}
	defer stream.Close()

	if err := writeFrame(stream, data); err != nil {
		logger.Debug("[quic-inbound] 发送请求失败: %v", err)
		return
	}

	stream.SetReadDeadline(time.Now().Add(udpReadTimeout))
	resp, err := readFrame(stream)
	if err != nil {
		if err != io.EOF {
			logger.Debug("[quic-inbound] 读取响应失败: %v", err)
		}
		return
	}
	if len(resp) == 0 {
		return
	}

	ib.stats.bytesOut.Add(int64(len(resp)))
	localConn.WriteToUDP(resp, clientAddr)
}

// ─────────────────────────────────────────────────
// Outbound：境外UDP出口，QUIC服务端
// ─────────────────────────────────────────────────

type outboundStats struct {
	totalConns  atomic.Int64
	activeConns atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

type Outbound struct {
	cfg        *config.MergedConfig
	targetAddr *net.UDPAddr // 预解析，避免每个 stream 重复 DNS 解析
	stats      outboundStats
	sem        chan struct{}
}

func NewOutbound(cfg *config.MergedConfig) *Outbound {
	ob := &Outbound{cfg: cfg}
	if cfg.MaxConns > 0 {
		ob.sem = make(chan struct{}, cfg.MaxConns)
	}
	return ob
}

func (ob *Outbound) Run() error {
	// 预解析目标地址
	targetAddr, err := net.ResolveUDPAddr("udp", ob.cfg.Remote)
	if err != nil {
		return fmt.Errorf("解析目标UDP地址失败: %w", err)
	}
	ob.targetAddr = targetAddr

	cert, err := tls.LoadX509KeyPair(ob.cfg.Cert, ob.cfg.Key)
	if err != nil {
		return fmt.Errorf("加载证书失败: %w", err)
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

	maxConnsStr := "unlimited"
	if ob.cfg.MaxConns > 0 {
		maxConnsStr = fmt.Sprintf("%d", ob.cfg.MaxConns)
	}
	logger.Info("[quic-outbound] QUIC监听 %s → %s  max_conns=%s", ob.cfg.Listen, ob.cfg.Remote, maxConnsStr)

	go ob.statsLoop()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logger.Error("[quic-outbound] accept error: %v", err)
			continue
		}

		if ob.sem != nil {
			select {
			case ob.sem <- struct{}{}:
			default:
				logger.Warn("[quic-outbound:%s] 连接数已达上限 %d，拒绝", ob.cfg.Listen, ob.cfg.MaxConns)
				conn.CloseWithError(0, "too many connections")
				continue
			}
		}

		go ob.handleConn(conn)
	}
}

func (ob *Outbound) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("[quic-outbound:%s] 统计 | 累计连接: %d  活跃: %d  收: %s  发: %s",
			ob.cfg.Listen,
			ob.stats.totalConns.Load(),
			ob.stats.activeConns.Load(),
			formatBytes(ob.stats.bytesIn.Load()),
			formatBytes(ob.stats.bytesOut.Load()),
		)
	}
}

func (ob *Outbound) handleConn(conn *quicgo.Conn) {
	defer func() {
		conn.CloseWithError(0, "done")
		ob.stats.activeConns.Add(-1)
		if ob.sem != nil {
			<-ob.sem
		}
	}()

	ob.stats.totalConns.Add(1)
	ob.stats.activeConns.Add(1)

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
		logger.Warn("[quic-outbound] 认证失败 from %s", conn.RemoteAddr())
		conn.CloseWithError(1, "auth failed")
		return
	}
	logger.Debug("[quic-outbound] QUIC认证成功: %s", conn.RemoteAddr())

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go ob.handleStream(stream)
	}
}

// handleStream 修复：每个 stream 独立 UDPConn，完全并发，无锁争用
func (ob *Outbound) handleStream(stream *quicgo.Stream) {
	defer stream.Close()

	stream.SetReadDeadline(time.Now().Add(udpReadTimeout))
	data, err := readFrame(stream)
	if err != nil || len(data) == 0 {
		return
	}

	ob.stats.bytesIn.Add(int64(len(data)))

	// 每个 stream 独立建立 UDPConn，避免共享连接串行化
	udpConn, err := net.DialUDP("udp", nil, ob.targetAddr)
	if err != nil {
		logger.Error("[quic-outbound] 连接目标UDP失败: %v", err)
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

	ob.stats.bytesOut.Add(int64(n))

	if err := writeFrame(stream, buf[:n]); err != nil {
		return
	}
	logger.Debug("[quic-outbound] stream#%d %s→%s", stream.StreamID(), formatBytes(int64(len(data))), formatBytes(int64(n)))
}