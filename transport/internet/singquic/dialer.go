package singquic

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// Hysteria2OutboundConfig holds the configuration needed to initialize Hysteria2 client
type Hysteria2OutboundConfig struct {
	Destination net.Destination
	Password    string
	ServerPorts []string
	HopInterval string
	UpMbps      uint64
	DownMbps    uint64
	Obfs        *Hysteria2ObfsConfig
}

// Hysteria2ObfsConfig holds obfuscation configuration
type Hysteria2ObfsConfig struct {
	Type     string
	Password string
}

// Context keys for passing Hysteria2 configuration
type hysteria2ConfigKey struct{}
type hysteria2ClientCacheKey struct{}

// Hysteria2ClientCache holds the initialized client with sync.Once for thread-safe initialization
type Hysteria2ClientCache struct {
	Client     *hysteria2.Client
	ClientOnce sync.Once
	ClientErr  error
}

// ContextWithHysteria2Config adds Hysteria2 outbound config to context
func ContextWithHysteria2Config(ctx context.Context, config *Hysteria2OutboundConfig) context.Context {
	return context.WithValue(ctx, hysteria2ConfigKey{}, config)
}

// Hysteria2ConfigFromContext retrieves Hysteria2 config from context
func Hysteria2ConfigFromContext(ctx context.Context) *Hysteria2OutboundConfig {
	if config, ok := ctx.Value(hysteria2ConfigKey{}).(*Hysteria2OutboundConfig); ok {
		return config
	}
	return nil
}

// ContextWithHysteria2ClientCache adds client cache to context
func ContextWithHysteria2ClientCache(ctx context.Context, cache *Hysteria2ClientCache) context.Context {
	return context.WithValue(ctx, hysteria2ClientCacheKey{}, cache)
}

// Hysteria2ClientCacheFromContext retrieves client cache from context
func Hysteria2ClientCacheFromContext(ctx context.Context) *Hysteria2ClientCache {
	if cache, ok := ctx.Value(hysteria2ClientCacheKey{}).(*Hysteria2ClientCache); ok {
		return cache
	}
	return nil
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

// EnsureHysteria2Client ensures the Hysteria2 client is initialized
// This is useful for UDP connections which need the client but don't go through dialHysteria2
func EnsureHysteria2Client(ctx context.Context, streamSettings *internet.MemoryStreamConfig) error {
	// Get config and client cache from context
	config := Hysteria2ConfigFromContext(ctx)
	if config == nil {
		return errors.New("Hysteria2 config not found in context")
	}

	clientCache := Hysteria2ClientCacheFromContext(ctx)
	if clientCache == nil {
		return errors.New("Hysteria2 client cache not found in context")
	}

	// Initialize client on first call (thread-safe with sync.Once)
	clientCache.ClientOnce.Do(func() {
		errors.LogInfo(ctx, "initializing Hysteria2 client to ", config.Destination.NetAddr())
		clientCache.Client, clientCache.ClientErr = initHysteria2Client(ctx, config, streamSettings)
		if clientCache.ClientErr == nil {
			errors.LogInfo(ctx, "Hysteria2 client initialized successfully")
		}
	})

	if clientCache.ClientErr != nil {
		return errors.New("failed to initialize Hysteria2 client").Base(clientCache.ClientErr)
	}

	return nil
}

// dialHysteria2 creates a Hysteria2 connection, initializing the client on first call
func dialHysteria2(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	// Ensure client is initialized
	if err := EnsureHysteria2Client(ctx, streamSettings); err != nil {
		return nil, err
	}

	// Get client cache from context
	clientCache := Hysteria2ClientCacheFromContext(ctx)
	if clientCache == nil || clientCache.Client == nil {
		return nil, errors.New("Hysteria2 client not available")
	}

	// Create connection through Hysteria2 client
	if dest.Network == net.Network_TCP {
		conn, err := clientCache.Client.DialConn(ctx, singbridge.ToSocksaddr(dest))
		if err != nil {
			return nil, errors.New("failed to dial Hysteria2 TCP connection").Base(err)
		}
		return stat.Connection(conn), nil
	}

	// For UDP, we can't return a simple connection since Hysteria2 uses PacketConn
	// This should be handled at the proxy layer using ListenPacket
	return nil, errors.New("Hysteria2 UDP connections should use client.ListenPacket at proxy layer")
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

// initHysteria2Client initializes a new Hysteria2 client with the given configuration
func initHysteria2Client(ctx context.Context, config *Hysteria2OutboundConfig, streamSettings *internet.MemoryStreamConfig) (*hysteria2.Client, error) {
	// Get TLS config from streamSettings
	goTLSConfig, err := GetTLSConfigFromStreamSettings(streamSettings, config.Destination)
	if err != nil {
		return nil, errors.New("failed to get TLS config from streamSettings").Base(err)
	}

	tlsConfig := singbridge.NewTLSConfig(goTLSConfig)

	// Create basic UDP dialer for QUIC
	udpDialer := &basicUDPDialer{
		dest:         config.Destination,
		socketConfig: streamSettings.SocketSettings,
	}
	singDialer := singbridge.NewDialer(udpDialer)

	// Calculate bandwidth (convert Mbps to Bps)
	var sendBPS uint64
	var receiveBPS uint64
	if config.UpMbps > 0 {
		sendBPS = config.UpMbps * 125000 // 1 Mbps = 125000 Bps
	}
	if config.DownMbps > 0 {
		receiveBPS = config.DownMbps * 125000
	}

	// Get salamander password from obfs config
	var salamanderPassword string
	if config.Obfs != nil && config.Obfs.Type == "salamander" {
		salamanderPassword = config.Obfs.Password
		errors.LogInfo(ctx, "Hysteria2 salamander obfuscation enabled")
	}

	// Parse hop interval for port hopping
	var hopInterval time.Duration
	if config.HopInterval != "" {
		var err error
		hopInterval, err = time.ParseDuration(config.HopInterval)
		if err != nil {
			return nil, errors.New("invalid hop_interval format").Base(err)
		}
		errors.LogInfo(ctx, "Hysteria2 port hopping enabled with interval: ", hopInterval)
	}

	// Create Hysteria2 client options
	// IMPORTANT: Use context.Background() instead of request ctx to avoid client being affected by request cancellation
	// The client is long-lived and shared across multiple requests, so it should not be tied to any single request
	clientOptions := hysteria2.ClientOptions{
		Context:            context.Background(),
		Dialer:             singDialer,
		Logger:             singbridge.NewLogger(errors.New),
		ServerAddress:      singbridge.ToSocksaddr(config.Destination),
		ServerPorts:        config.ServerPorts,
		HopInterval:        hopInterval,
		Password:           config.Password,
		TLSConfig:          tlsConfig,
		SendBPS:            sendBPS,
		ReceiveBPS:         receiveBPS,
		SalamanderPassword: salamanderPassword,
		UDPDisabled:        false,
	}

	// Create the client
	client, err := hysteria2.NewClient(clientOptions)
	if err != nil {
		return nil, errors.New("failed to create Hysteria2 client").Base(err)
	}

	return client, nil
}

// dialTUIC creates a TUIC connection (placeholder for now)
func dialTUIC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	return nil, errors.New("TUIC dialer not implemented yet")
}

func init() {
	// Register transport dialers for QUIC-based protocols
	// These dialers expect the client to be initialized and stored in context
	common.Must(internet.RegisterTransportDialer(ProtocolNameHysteria2, dialHysteria2))
	common.Must(internet.RegisterTransportDialer(ProtocolNameTUIC, dialTUIC))
}
