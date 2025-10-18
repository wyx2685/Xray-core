package tuic

import (
	"context"

	"github.com/sagernet/sing-quic/tuic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutbound(ctx, config.(*ClientConfig))
	}))
}

// Outbound is the TUIC outbound handler
type Outbound struct {
	ctx           context.Context
	config        *ClientConfig
	server        *protocol.ServerSpec
	policyManager policy.Manager
	dns           dns.Client
	client        *tuic.Client
}

// NewOutbound creates a new TUIC outbound handler
func NewOutbound(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config == nil {
		return nil, newError("TUIC outbound config is nil")
	}

	if len(config.Server) == 0 {
		return nil, newError("no server specified")
	}

	serverSpec, err := protocol.NewServerSpecFromPB(config.Server[0])
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	v := core.MustFromContext(ctx)
	outbound := &Outbound{
		ctx:           ctx,
		config:        config,
		server:        serverSpec,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	if err := core.RequireFeatures(ctx, func(dnsClient dns.Client) error {
		outbound.dns = dnsClient
		return nil
	}); err != nil {
		return nil, err
	}

	return outbound, nil
}

// Process processes an outbound connection
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundsFromContext(ctx)
	if len(outbound) == 0 || !outbound[0].Target.IsValid() {
		return newError("invalid outbound target")
	}

	target := outbound[0].Target

	// Get user account
	var account *MemoryAccount
	if o.server.User != nil {
		if acc, ok := o.server.User.Account.(*MemoryAccount); ok {
			account = acc
		}
	}

	if account == nil {
		return newError("TUIC outbound user not found or invalid account type")
	}

	// TODO: Complete TUIC client implementation
	// This requires proper TLS configuration and connection handling
	_ = account
	_ = target

	return newError("TUIC outbound not fully implemented yet")
}
