package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/tuic"
	"google.golang.org/protobuf/proto"
)

// TuicUserConfig is user configuration for TUIC
type TuicUserConfig struct {
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// TuicServerConfig is Inbound configuration for TUIC
type TuicServerConfig struct {
	Users             []*TuicUserConfig `json:"users"`
	CongestionControl string            `json:"congestionControl"`
	AuthTimeout       uint32            `json:"authTimeout"`
	ZeroRttHandshake  bool              `json:"zeroRttHandshake"`
	Heartbeat         uint32            `json:"heartbeat"`
	UdpTimeout        uint32            `json:"udpTimeout"`
}

// Build implements Buildable
func (c *TuicServerConfig) Build() (proto.Message, error) {
	config := &tuic.ServerConfig{
		Users:             make([]*protocol.User, 0, len(c.Users)),
		CongestionControl: c.CongestionControl,
		AuthTimeout:       c.AuthTimeout,
		ZeroRttHandshake:  c.ZeroRttHandshake,
		Heartbeat:         c.Heartbeat,
		UdpTimeout:        c.UdpTimeout,
	}

	// Set defaults
	if config.CongestionControl == "" {
		config.CongestionControl = "cubic"
	}
	if config.AuthTimeout == 0 {
		config.AuthTimeout = 3
	}
	if config.Heartbeat == 0 {
		config.Heartbeat = 10
	}
	if config.UdpTimeout == 0 {
		config.UdpTimeout = 60
	}

	// Build users
	for _, user := range c.Users {
		if user.UUID == "" {
			return nil, errors.New("TUIC: UUID is required for user")
		}
		if user.Password == "" {
			return nil, errors.New("TUIC: password is required for user")
		}

		account := &tuic.Account{
			Uuid:     user.UUID,
			Password: user.Password,
		}

		config.Users = append(config.Users, &protocol.User{
			Level:   uint32(user.Level),
			Email:   user.Email,
			Account: serial.ToTypedMessage(account),
		})
	}

	return config, nil
}

// TuicServerTarget is configuration of a single TUIC server
type TuicServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	UUID     string   `json:"uuid"`
	Password string   `json:"password"`
}

// TuicClientConfig is Outbound configuration for TUIC
type TuicClientConfig struct {
	Address           *Address            `json:"address"`
	Port              uint16              `json:"port"`
	Level             byte                `json:"level"`
	Email             string              `json:"email"`
	UUID              string              `json:"uuid"`
	Password          string              `json:"password"`
	Servers           []*TuicServerTarget `json:"servers"`
	CongestionControl string              `json:"congestionControl"`
	UdpStream         bool                `json:"udpStream"`
	ZeroRttHandshake  bool                `json:"zeroRttHandshake"`
	Heartbeat         uint32              `json:"heartbeat"`
}

// Build implements Buildable
func (c *TuicClientConfig) Build() (proto.Message, error) {
	// Support single server or servers array
	if c.Address != nil {
		c.Servers = []*TuicServerTarget{
			{
				Address:  c.Address,
				Port:     c.Port,
				Level:    c.Level,
				Email:    c.Email,
				UUID:     c.UUID,
				Password: c.Password,
			},
		}
	}

	if len(c.Servers) == 0 {
		return nil, errors.New("TUIC: no server configured")
	}

	if len(c.Servers) > 1 {
		return nil, errors.New("TUIC: multiple servers not supported, use multiple outbounds instead")
	}

	config := &tuic.ClientConfig{
		CongestionControl: c.CongestionControl,
		UdpStream:         c.UdpStream,
		ZeroRttHandshake:  c.ZeroRttHandshake,
		Heartbeat:         c.Heartbeat,
	}

	// Set defaults
	if config.CongestionControl == "" {
		config.CongestionControl = "cubic"
	}
	if config.Heartbeat == 0 {
		config.Heartbeat = 10
	}

	for _, server := range c.Servers {
		if server.Address == nil {
			return nil, errors.New("TUIC: server address is not set")
		}
		if server.Port == 0 {
			return nil, errors.New("TUIC: invalid server port")
		}
		if server.UUID == "" {
			return nil, errors.New("TUIC: UUID is not specified")
		}
		if server.Password == "" {
			return nil, errors.New("TUIC: password is not specified")
		}

		config.Server = append(config.Server, &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: &protocol.User{
				Level: uint32(server.Level),
				Email: server.Email,
				Account: serial.ToTypedMessage(&tuic.Account{
					Uuid:     server.UUID,
					Password: server.Password,
				}),
			},
		})

		break
	}

	return config, nil
}
