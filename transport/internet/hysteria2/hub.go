package hysteria2

import (
	"context"
	gonet "net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	hy2proxy "github.com/xtls/xray-core/proxy/hysteria2"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// Listener implements internet.Listener for Hysteria2 protocol
type Listener struct {
	proxyInbound *hy2proxy.Inbound
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

// Listen creates a new Hysteria2 listener
func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if streamSettings == nil || streamSettings.SecuritySettings == nil {
		return nil, errors.New("Hysteria2 requires TLS")
	}

	tlsConfig, ok := streamSettings.SecuritySettings.(*xtls.Config)
	if !ok || tlsConfig == nil {
		return nil, errors.New("Hysteria2 requires TLS configuration")
	}

	// Get proxy inbound from context
	var proxyInbound *hy2proxy.Inbound
	if v := ctx.Value("xray_proxy_inbound"); v != nil {
		if inbound, ok := v.(*hy2proxy.Inbound); ok {
			proxyInbound = inbound
		}
	}

	if proxyInbound == nil {
		return nil, errors.New("Hysteria2 requires proxy.Inbound from context")
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
		return nil, errors.New("Failed to get TLS config")
	}

	// Create listener context
	listenerCtx, cancel := context.WithCancel(ctx)

	// Start service in proxy layer with the same context (contains dispatcher)
	if err := proxyInbound.StartService(ctx, tag, udpConn, serverTLSConfig); err != nil {
		cancel()
		udpConn.Close()
		return nil, errors.New("Failed to start Hysteria2 service").Base(err)
	}

	errors.LogInfo(ctx, "Hysteria2 server listening on ", address, ":", port)

	listener := &Listener{
		proxyInbound: proxyInbound,
		rawConn:      udpConn,
		ctx:          listenerCtx,
		cancel:       cancel,
	}

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
