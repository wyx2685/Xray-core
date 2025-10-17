package hysteria2

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	CanNotUseUDPExtension = "Only hysteria2 proxy protocol can use udpExtension."
	Hy2MustNeedTLS        = "Hysteria2 based on QUIC that requires TLS."
)

// HyConn wraps a QUIC stream for Hysteria2 protocol
type HyConn struct {
	stream quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *HyConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *HyConn) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *HyConn) Close() error {
	return c.stream.Close()
}

func (c *HyConn) LocalAddr() net.Addr {
	return c.local
}

func (c *HyConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *HyConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *HyConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *HyConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
