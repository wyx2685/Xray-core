package singquic

import (
	"context"
	"crypto/tls"
	gonet "net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// QuicInbound defines the interface that QUIC-based proxy inbounds must implement
type QuicInbound interface {
	StartService(ctx context.Context, tag string, packetConn gonet.PacketConn, tlsConfig *tls.Config) error
	Close() error
}

// Listener implements internet.Listener for QUIC-based protocols
type Listener struct {
	proxyInbound QuicInbound
	rawConn      gonet.PacketConn
	ctx          context.Context
	cancel       context.CancelFunc
}

// Addr implements internet.Listener.Addr
func (l *Listener) Addr() gonet.Addr {
	return l.rawConn.LocalAddr()
}

// Close implements internet.Listener.Close
func (l *Listener) Close() error {
	l.cancel()
	if l.proxyInbound != nil {
		l.proxyInbound.Close()
	}
	return l.rawConn.Close()
}

// Listen creates a new QUIC-based protocol listener
// This is a generic implementation for all QUIC-based protocols (Hysteria2, TUIC, etc.)
func Listen(
	ctx context.Context,
	address net.Address,
	port net.Port,
	streamSettings *internet.MemoryStreamConfig,
	handler internet.ConnHandler,
	protocolName string,
) (internet.Listener, error) {
	if streamSettings == nil || streamSettings.SecuritySettings == nil {
		return nil, errors.New(protocolName, " requires TLS")
	}

	tlsConfig, ok := streamSettings.SecuritySettings.(*xtls.Config)
	if !ok || tlsConfig == nil {
		return nil, errors.New(protocolName, " requires TLS configuration")
	}

	// Get proxy inbound from context
	var proxyInbound QuicInbound
	if v := ctx.Value("xray_proxy_inbound"); v != nil {
		if inbound, ok := v.(QuicInbound); ok {
			proxyInbound = inbound
		}
	}

	if proxyInbound == nil {
		return nil, errors.New(protocolName, " requires proxy.Inbound from context")
	}

	var tag string
	if v := ctx.Value("inbound_tag"); v != nil {
		if t, ok := v.(string); ok {
			tag = t
		}
	}

	// Create UDP packet connection
	udpConn, err := internet.ListenSystemPacket(ctx, &gonet.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	// Get TLS config from Xray
	serverTLSConfig := tlsConfig.GetTLSConfig(xtls.WithNextProto("h3"))
	if serverTLSConfig == nil {
		udpConn.Close()
		return nil, errors.New("Failed to get TLS config for ", protocolName)
	}

	// Create listener context
	listenerCtx, cancel := context.WithCancel(ctx)

	// Start service in proxy layer with the same context (contains dispatcher)
	if err := proxyInbound.StartService(ctx, tag, udpConn, serverTLSConfig); err != nil {
		cancel()
		udpConn.Close()
		return nil, errors.New("Failed to start ", protocolName, " service").Base(err)
	}

	errors.LogInfo(ctx, protocolName, " server listening on ", address, ":", port)

	listener := &Listener{
		proxyInbound: proxyInbound,
		rawConn:      udpConn,
		ctx:          listenerCtx,
		cancel:       cancel,
	}

	return listener, nil
}

// listenerCreator creates a listener for a specific protocol name
func listenerCreator(protocolName string) internet.ListenFunc {
	return func(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
		return Listen(ctx, address, port, streamSettings, handler, protocolName)
	}
}

func init() {
	// Register transport listeners for sing-quic based protocols
	common.Must(internet.RegisterTransportListener(ProtocolNameHysteria2, listenerCreator(ProtocolNameHysteria2)))
	common.Must(internet.RegisterTransportListener(ProtocolNameTUIC, listenerCreator(ProtocolNameTUIC)))
}
