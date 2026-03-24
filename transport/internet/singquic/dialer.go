package singquic

import (
	"context"
	"crypto/tls"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// GetTLSConfigFromStreamSettings extracts TLS configuration from streamSettings
// This is used by QUIC-based protocols (Hysteria2, TUIC, etc.) to get TLS config for client connections
func GetTLSConfigFromStreamSettings(streamSettings *internet.MemoryStreamConfig, destination net.Destination) (*tls.Config, error) {
	if streamSettings == nil {
		return nil, errors.New("streamSettings is nil")
	}

	// Verify that network protocol is set to a QUIC-based protocol
	protocolName := streamSettings.ProtocolName
	if protocolName != ProtocolNameTUIC {
		return nil, errors.New("streamSettings network must be '", ProtocolNameTUIC, "', got: ", protocolName)
	}

	// Get TLS config from streamSettings
	tlsConfig := xtls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		// No TLS config in streamSettings, create default one
		return &tls.Config{
			ServerName: destination.Address.String(),
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
		}, nil
	}

	// Get Go's tls.Config with h3 ALPN for QUIC
	goTLSConfig := tlsConfig.GetTLSConfig(xtls.WithNextProto("h3"), xtls.WithDestination(destination))
	return goTLSConfig, nil
}

// basicUDPDialer is a minimal UDP dialer for QUIC
type basicUDPDialer struct {
	dest         net.Destination
	socketConfig *internet.SocketConfig
}

func (d *basicUDPDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	udpDest := net.Destination{
		Network: net.Network_UDP,
		Address: d.dest.Address,
		Port:    d.dest.Port,
	}
	conn, err := internet.DialSystem(ctx, udpDest, d.socketConfig)
	if err != nil {
		return nil, err
	}
	return stat.Connection(conn), nil
}

func (d *basicUDPDialer) DestIpAddress() net.IP {
	return nil
}

func (d *basicUDPDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {
	// Not used for UDP
}

// dialTUIC creates a TUIC connection (placeholder for now)
func dialTUIC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	return nil, errors.New("TUIC dialer not implemented yet")
}

func init() {
	// Register transport dialers for QUIC-based protocols
	// These dialers expect the client to be initialized and stored in context
	common.Must(internet.RegisterTransportDialer(ProtocolNameTUIC, dialTUIC))
}
