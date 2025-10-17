package singbridge

import (
	"crypto/tls"
	gonet "net"

	singTLS "github.com/sagernet/sing/common/tls"
)

var (
	_ singTLS.ServerConfig = (*TLSConfig)(nil)
	_ singTLS.Config       = (*TLSConfig)(nil)
)

// TLSConfig wraps Go's tls.Config for sing's TLS interface
type TLSConfig struct {
	config *tls.Config
}

func NewTLSConfig(config *tls.Config) singTLS.ServerConfig {
	return &TLSConfig{config: config}
}

func (c *TLSConfig) ServerName() string {
	return c.config.ServerName
}

func (c *TLSConfig) SetServerName(name string) {
	c.config.ServerName = name
}

func (c *TLSConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *TLSConfig) SetNextProtos(protos []string) {
	c.config.NextProtos = protos
}

func (c *TLSConfig) Config() (*tls.Config, error) {
	return c.config, nil
}

func (c *TLSConfig) STDConfig() (*singTLS.STDConfig, error) {
	return c.config, nil
}

func (c *TLSConfig) Start() error {
	return nil
}

func (c *TLSConfig) Close() error {
	return nil
}

func (c *TLSConfig) Server(conn gonet.Conn) (singTLS.Conn, error) {
	return tls.Server(conn, c.config), nil
}

func (c *TLSConfig) Clone() singTLS.Config {
	return &TLSConfig{config: c.config.Clone()}
}

func (c *TLSConfig) Client(conn gonet.Conn) (singTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}
