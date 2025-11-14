package hysteria2

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/singquic"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

// Outbound is the Hysteria2 outbound proxy handler
type Outbound struct {
	ctx           context.Context
	config        *ClientConfig
	server        *protocol.ServerSpec
	policyManager policy.Manager
	account       *MemoryAccount                    // Cached account to avoid repeated type assertions
	clientCache   *singquic.Hysteria2ClientCache    // Cache for initialized client
	hy2Config     *singquic.Hysteria2OutboundConfig // Cached config to avoid repeated creation
}

// NewClient creates a new Hysteria2 outbound handler
func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config == nil {
		return nil, errors.New("Hysteria2 client config is nil")
	}

	if config.Server == nil {
		return nil, errors.New("Hysteria2: no server specified")
	}

	serverSpec, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to parse server spec").Base(err)
	}

	v := core.MustFromContext(ctx)

	// Cache account to avoid repeated type assertions in Process()
	var account *MemoryAccount
	if serverSpec.User != nil {
		if acc, ok := serverSpec.User.Account.(*MemoryAccount); ok {
			account = acc
		}
	}
	if account == nil {
		return nil, errors.New("Hysteria2: user account not found or invalid")
	}

	// Prepare Hysteria2 configuration once to avoid repeated creation
	var obfsConfig *singquic.Hysteria2ObfsConfig
	if config.Obfs != nil {
		obfsConfig = &singquic.Hysteria2ObfsConfig{
			Type:     config.Obfs.Type,
			Password: config.Obfs.Password,
		}
	}

	hy2Config := &singquic.Hysteria2OutboundConfig{
		Destination: serverSpec.Destination,
		Password:    account.Password,
		ServerPorts: config.ServerPorts,
		HopInterval: config.HopInterval,
		UpMbps:      config.UpMbps,
		DownMbps:    config.DownMbps,
		Obfs:        obfsConfig,
	}

	outbound := &Outbound{
		ctx:           ctx,
		config:        config,
		server:        serverSpec,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		account:       account,
		clientCache:   &singquic.Hysteria2ClientCache{},
		hy2Config:     hy2Config,
	}

	return outbound, nil
}

// Process implements proxy.Outbound.Process()
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || !outbounds[0].Target.IsValid() {
		return errors.New("target not specified")
	}

	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "hysteria2"
	ob.CanSpliceCopy = 3

	destination := ob.Target

	// Add config and client cache to context so transport layer can initialize client
	ctx = singquic.ContextWithHysteria2Config(ctx, o.hy2Config)
	ctx = singquic.ContextWithHysteria2ClientCache(ctx, o.clientCache)

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", o.server.Destination.NetAddr())

	// Handle connection based on network type
	switch destination.Network {
	case net.Network_TCP:
		// Use dialer.Dial() which will call the registered Hysteria2 transport dialer
		// This allows streamSettings to be properly used for TLS configuration
		return o.handleTCPConnViaDial(ctx, link, destination, dialer)
	case net.Network_UDP:
		// UDP needs to ensure client is initialized first, then use ListenPacket
		return o.handleUDPConn(ctx, link, destination, dialer)
	default:
		return errors.New("unsupported network type: ", destination.Network)
	}
}

// handleTCPConnViaDial handles TCP connections using dialer.Dial() for proper streamSettings flow
func (o *Outbound) handleTCPConnViaDial(ctx context.Context, link *transport.Link, destination net.Destination, dialer internet.Dialer) error {
	// Get inbound connection for potential splice copy optimization
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	// Dial through dialer - this will trigger Handler.Dial() -> internet.Dial() -> dialHysteria2()
	// The streamSettings will be automatically passed through this flow
	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return errors.New("failed to dial TCP connection through dialer").Base(err)
	}
	defer conn.Close()

	// Use singbridge to copy data bidirectionally
	return singbridge.CopyConn(ctx, inboundConn, link, conn)
}

// handleUDPConn handles UDP connections over Hysteria2
func (o *Outbound) handleUDPConn(ctx context.Context, link *transport.Link, destination net.Destination, dialer internet.Dialer) error {
	// Get inbound connection
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	// Ensure client is initialized
	// For UDP, we need to trigger dialer.Dial() once to ensure client is initialized with proper streamSettings
	// The dialer.Dial() call will go through Handler.Dial() -> internet.Dial() -> dialHysteria2()
	// which properly passes streamSettings from the Handler
	// Use sync.Once to ensure initialization only happens once even with concurrent requests
	o.clientCache.ClientOnce.Do(func() {
		// Use a TCP destination to trigger initialization (the actual network type doesn't matter for init)
		// We use the server destination to trigger client initialization
		initDest := net.TCPDestination(o.server.Destination.Address, o.server.Destination.Port)

		// This will trigger dialHysteria2() which initializes the client with proper streamSettings
		conn, err := dialer.Dial(ctx, initDest)
		if err != nil {
			o.clientCache.ClientErr = err
			return
		}
		// CRITICAL: Always close connection to prevent leak, even if we return early
		defer conn.Close()
	})

	// Check if initialization failed
	if o.clientCache.ClientErr != nil {
		return errors.New("failed to initialize Hysteria2 client for UDP").Base(o.clientCache.ClientErr)
	}

	// Create packet connection through Hysteria2
	packetConn, err := o.clientCache.Client.ListenPacket(ctx)
	if err != nil {
		return errors.New("failed to create packet connection").Base(err)
	}
	defer packetConn.Close()

	// Use singbridge to handle packet connection copying
	return singbridge.CopyPacketConn(ctx, inboundConn, link, destination, packetConn)
}

// Close closes the Hysteria2 client
func (o *Outbound) Close() error {
	if o.clientCache != nil && o.clientCache.Client != nil {
		return o.clientCache.Client.CloseWithError(errors.New("outbound closed"))
	}
	return nil
}

// Start implements common.Runnable
func (o *Outbound) Start() error {
	return nil
}
