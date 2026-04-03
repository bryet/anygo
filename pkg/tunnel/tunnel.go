package tunnel

import (
	"crypto/sha256"
	"io"
	"net"

	"anygo/config"
	"anygo/pkg/padding"
	"github.com/xtaci/smux"
)

// AuthToken 根据password生成32字节认证token
func AuthToken(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

// paddedConn 组合padding读写器和原始连接
type paddedConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func newPaddedConn(conn net.Conn, cfg config.PaddingConfig) *paddedConn {
	padCfg := padding.Config{Templates: cfg.Templates}
	return &paddedConn{
		Conn: conn,
		r:    padding.NewReader(conn),
		w:    padding.NewWriter(conn, padCfg),
	}
}

func (c *paddedConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *paddedConn) Write(b []byte) (int, error) { return c.w.Write(b) }

// NewClientSession 创建smux客户端session（inbound使用）
func NewClientSession(conn net.Conn, cfg config.PaddingConfig) (*smux.Session, error) {
	pc := newPaddedConn(conn, cfg)
	smuxCfg := smux.DefaultConfig()
	smuxCfg.KeepAliveInterval = 10
	smuxCfg.KeepAliveTimeout = 30
	return smux.Client(pc, smuxCfg)
}

// NewServerSession 创建smux服务端session（outbound使用）
func NewServerSession(conn net.Conn, cfg config.PaddingConfig) (*smux.Session, error) {
	pc := newPaddedConn(conn, cfg)
	smuxCfg := smux.DefaultConfig()
	smuxCfg.KeepAliveInterval = 10
	smuxCfg.KeepAliveTimeout = 30
	return smux.Server(pc, smuxCfg)
}
