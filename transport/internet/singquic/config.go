package singquic

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

// Protocol names for sing-quic based transports
const (
	ProtocolNameHysteria2 = "hysteria2"
	ProtocolNameTUIC      = "tuic"
)

func init() {
	// Register protocol config creators for sing-quic based protocols
	// Both protocols use the same empty Config since actual configuration
	// is handled at the proxy layer
	common.Must(internet.RegisterProtocolConfigCreator(ProtocolNameHysteria2, func() interface{} {
		return new(Config)
	}))
	common.Must(internet.RegisterProtocolConfigCreator(ProtocolNameTUIC, func() interface{} {
		return new(Config)
	}))
}
