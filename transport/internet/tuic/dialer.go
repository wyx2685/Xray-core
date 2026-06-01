package tuic

import (
	"context"
	"crypto/tls"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func GetTLSConfigFromStreamSettings(streamSettings *internet.MemoryStreamConfig, destination net.Destination) (*tls.Config, error) {
	if streamSettings == nil {
		return nil, errors.New("streamSettings is nil")
	}
	if streamSettings.ProtocolName != protocolName {
		return nil, errors.New("streamSettings network must be '", protocolName, "', got: ", streamSettings.ProtocolName)
	}

	tlsConfig := xtls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return &tls.Config{
			ServerName: destination.Address.String(),
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
		}, nil
	}
	return tlsConfig.GetTLSConfig(xtls.WithNextProto("h3"), xtls.WithDestination(destination)), nil
}

func dialTUIC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	return nil, errors.New("TUIC dialer not implemented yet")
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, dialTUIC))
}
