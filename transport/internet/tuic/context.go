package tuic

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

type Authenticator interface {
	Authenticate(ctx context.Context, uuid [16]byte, token []byte, tlsState tls.ConnectionState) (*protocol.MemoryUser, bool)
}

type authenticatorContextKey struct{}
type settingsContextKey struct{}

type ServerSettings struct {
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
}

func ContextWithAuthenticator(ctx context.Context, authenticator Authenticator) context.Context {
	return context.WithValue(ctx, authenticatorContextKey{}, authenticator)
}

func AuthenticatorFromContext(ctx context.Context) Authenticator {
	authenticator, _ := ctx.Value(authenticatorContextKey{}).(Authenticator)
	return authenticator
}

func ContextWithServerSettings(ctx context.Context, settings ServerSettings) context.Context {
	return context.WithValue(ctx, settingsContextKey{}, settings)
}

func ServerSettingsFromContext(ctx context.Context) ServerSettings {
	settings, _ := ctx.Value(settingsContextKey{}).(ServerSettings)
	return settings
}
