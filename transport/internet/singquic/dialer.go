package singquic

import (
	"context"
	"crypto/tls"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// UDPDialer implements internet.Dialer for QUIC-based protocols
type UDPDialer struct {
	Ctx          context.Context
	Destination  net.Destination
	SocketConfig *internet.SocketConfig
}

// Dial creates a UDP connection to the destination
func (d *UDPDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	// For QUIC protocols, we use UDP
	udpDest := net.Destination{
		Network: net.Network_UDP,
		Address: d.Destination.Address,
		Port:    d.Destination.Port,
	}

	conn, err := internet.DialSystem(ctx, udpDest, d.SocketConfig)
	if err != nil {
		return nil, err
	}
	return stat.Connection(conn), nil
}

// DestIpAddress returns the destination IP address
func (d *UDPDialer) DestIpAddress() net.IP {
	return nil
}

// SetOutboundGateway is not implemented for UDP dialer
func (d *UDPDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {
	// Not used for QUIC
}

// GetTLSConfigFromStreamSettings extracts TLS configuration from streamSettings
// This is used by QUIC-based protocols (Hysteria2, TUIC, etc.) to get TLS config for client connections
func GetTLSConfigFromStreamSettings(streamSettings *internet.MemoryStreamConfig, destination net.Destination) (*tls.Config, error) {
	if streamSettings == nil {
		return nil, errors.New("streamSettings is nil")
	}

	// Verify that network protocol is set to a QUIC-based protocol
	protocolName := streamSettings.ProtocolName
	if protocolName != ProtocolNameHysteria2 && protocolName != ProtocolNameTUIC {
		return nil, errors.New("streamSettings network must be '", ProtocolNameHysteria2, "' or '", ProtocolNameTUIC, "', got: ", protocolName)
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

func init() {
	// Note: QUIC-based protocols (Hysteria2, TUIC) don't use transport dialers like TCP/WS
	// They manage their own connections through sing-quic libraries
	// UDPDialer is a helper that provides UDP connectivity to sing-quic clients
	// Port hopping is handled internally by sing-quic hysteria2.Client
}
