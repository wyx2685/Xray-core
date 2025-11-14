package hysteria2

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"

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
	account       *MemoryAccount // Cached account to avoid repeated type assertions
	client        *hysteria2.Client
	clientOnce    sync.Once // Ensures client is initialized only once
	clientErr     error     // Stores initialization error
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

	outbound := &Outbound{
		ctx:           ctx,
		config:        config,
		server:        serverSpec,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		account:       account,
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

	// Initialize Hysteria2 client on first use (using sync.Once for better performance)
	o.clientOnce.Do(func() {
		errors.LogInfo(ctx, "initializing Hysteria2 client to ", o.server.Destination.NetAddr())
		o.clientErr = o.initClient(dialer)
		if o.clientErr == nil {
			errors.LogInfo(ctx, "Hysteria2 client initialized successfully")
		}
	})

	if o.clientErr != nil {
		return errors.New("failed to initialize Hysteria2 client").Base(o.clientErr)
	}

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", o.server.Destination.NetAddr())

	// Handle connection based on network type
	switch destination.Network {
	case net.Network_TCP:
		return o.handleTCPConn(ctx, link, destination)
	case net.Network_UDP:
		return o.handleUDPConn(ctx, link, destination)
	default:
		return errors.New("unsupported network type: ", destination.Network)
	}
}

// initClient initializes the Hysteria2 client with proper configuration
func (o *Outbound) initClient(dialer internet.Dialer) error {
	// Get streamSettings from dialer (Handler has streamSettings)
	var streamSettings *internet.MemoryStreamConfig
	if handler, ok := dialer.(interface {
		GetStreamSettings() *internet.MemoryStreamConfig
	}); ok {
		streamSettings = handler.GetStreamSettings()
	}

	if streamSettings == nil {
		return errors.New("Hysteria2 requires streamSettings with network='hysteria2'")
	}

	// Get TLS config from streamSettings
	goTLSConfig, err := singquic.GetTLSConfigFromStreamSettings(streamSettings, o.server.Destination)
	if err != nil {
		return errors.New("failed to get TLS config from streamSettings").Base(err)
	}

	tlsConfig := singbridge.NewTLSConfig(goTLSConfig)

	// Create UDP dialer for QUIC
	// Use o.ctx (outbound lifecycle) instead of request ctx to avoid context cancellation issues
	udpDialer := &singquic.UDPDialer{
		Ctx:          o.ctx,
		Destination:  o.server.Destination,
		SocketConfig: streamSettings.SocketSettings,
	}
	singDialer := singbridge.NewDialer(udpDialer)

	// Calculate bandwidth (convert Mbps to Bps)
	var sendBPS uint64
	var receiveBPS uint64
	if o.config.UpMbps > 0 {
		sendBPS = o.config.UpMbps * 125000 // 1 Mbps = 125000 Bps
	}
	if o.config.DownMbps > 0 {
		receiveBPS = o.config.DownMbps * 125000
	}

	// Get salamander password from obfs config
	var salamanderPassword string
	if o.config.Obfs != nil && o.config.Obfs.Type == "salamander" {
		salamanderPassword = o.config.Obfs.Password
		errors.LogInfo(o.ctx, "Hysteria2 salamander obfuscation enabled")
	}

	// Parse hop interval for port hopping
	var hopInterval time.Duration
	if o.config.HopInterval != "" {
		var err error
		hopInterval, err = time.ParseDuration(o.config.HopInterval)
		if err != nil {
			return errors.New("invalid hop_interval format").Base(err)
		}
		errors.LogInfo(o.ctx, "Hysteria2 port hopping enabled with interval: ", hopInterval)
	}

	// Create Hysteria2 client options
	// Use o.ctx (outbound lifecycle context) for client lifecycle management
	clientOptions := hysteria2.ClientOptions{
		Context:            o.ctx,
		Dialer:             singDialer,
		Logger:             singbridge.NewLogger(errors.New),
		ServerAddress:      singbridge.ToSocksaddr(o.server.Destination),
		ServerPorts:        o.config.ServerPorts,
		HopInterval:        hopInterval,
		Password:           o.account.Password,
		TLSConfig:          tlsConfig,
		SendBPS:            sendBPS,
		ReceiveBPS:         receiveBPS,
		SalamanderPassword: salamanderPassword,
		UDPDisabled:        false,
	}

	// Create the client
	client, err := hysteria2.NewClient(clientOptions)
	if err != nil {
		return errors.New("failed to create Hysteria2 client").Base(err)
	}

	o.client = client
	return nil
}

// handleTCPConn handles TCP connections over Hysteria2
func (o *Outbound) handleTCPConn(ctx context.Context, link *transport.Link, destination net.Destination) error {
	// Get inbound connection for potential splice copy optimization
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	// Dial TCP connection through Hysteria2
	conn, err := o.client.DialConn(ctx, singbridge.ToSocksaddr(destination))
	if err != nil {
		return errors.New("failed to dial TCP connection").Base(err)
	}
	defer conn.Close()

	// Use singbridge to copy data bidirectionally
	return singbridge.CopyConn(ctx, inboundConn, link, conn)
}

// handleUDPConn handles UDP connections over Hysteria2
func (o *Outbound) handleUDPConn(ctx context.Context, link *transport.Link, destination net.Destination) error {
	// Get inbound connection
	var inboundConn net.Conn
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inboundConn = inbound.Conn
	}

	// Create packet connection through Hysteria2
	packetConn, err := o.client.ListenPacket(ctx)
	if err != nil {
		return errors.New("failed to create packet connection").Base(err)
	}
	defer packetConn.Close()

	// Use singbridge to handle packet connection copying
	return singbridge.CopyPacketConn(ctx, inboundConn, link, destination, packetConn)
}

// Close closes the Hysteria2 client
func (o *Outbound) Close() error {
	if o.client != nil {
		return o.client.CloseWithError(errors.New("outbound closed"))
	}
	return nil
}

// Start implements common.Runnable
func (o *Outbound) Start() error {
	return nil
}
