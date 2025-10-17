package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/hysteria2"
	"google.golang.org/protobuf/proto"
)

// Hysteria2UserConfig is user configuration for Hysteria2
type Hysteria2UserConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// Hysteria2ObfsConfig is obfuscation configuration
type Hysteria2ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// Hysteria2MasqueradeConfig is masquerade configuration
type Hysteria2MasqueradeConfig struct {
	Type         string            `json:"type"`
	SimpleConfig string            `json:"simple_config"`
	Directory    string            `json:"directory"`
	URL          string            `json:"url"`
	RewriteHost  bool              `json:"rewrite_host"`
	StatusCode   uint32            `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Content      string            `json:"content"`
}

// Hysteria2ServerConfig is Inbound configuration for Hysteria2
type Hysteria2ServerConfig struct {
	Users                 []*Hysteria2UserConfig     `json:"users"`
	UpMbps                uint64                     `json:"up_mbps"`
	DownMbps              uint64                     `json:"down_mbps"`
	IgnoreClientBandwidth bool                       `json:"ignore_client_bandwidth"`
	Obfs                  *Hysteria2ObfsConfig       `json:"obfs"`
	Masquerade            *Hysteria2MasqueradeConfig `json:"masquerade"`
	BrutalDebug           bool                       `json:"brutal_debug"`
	PacketEncoding        uint32                     `json:"packet_encoding"`
}

// Build implements Buildable
func (c *Hysteria2ServerConfig) Build() (proto.Message, error) {
	config := &hysteria2.ServerConfig{
		Users:                 make([]*protocol.User, 0, len(c.Users)),
		UpMbps:                c.UpMbps,
		DownMbps:              c.DownMbps,
		IgnoreClientBandwidth: c.IgnoreClientBandwidth,
		BrutalDebug:           c.BrutalDebug,
		PacketEncoding:        c.PacketEncoding,
	}

	// Build users
	for _, user := range c.Users {
		if user.Password == "" {
			return nil, errors.New("Hysteria2: password is required for user")
		}

		account := &hysteria2.Account{
			Password: user.Password,
		}

		config.Users = append(config.Users, &protocol.User{
			Level:   uint32(user.Level),
			Email:   user.Email,
			Account: serial.ToTypedMessage(account),
		})
	}

	// Build obfuscation config
	if c.Obfs != nil {
		if c.Obfs.Type != "" && c.Obfs.Type != "salamander" {
			return nil, errors.New("Hysteria2: only 'salamander' obfuscation type is supported")
		}

		config.Obfs = &hysteria2.Obfs{
			Type:     c.Obfs.Type,
			Password: c.Obfs.Password,
		}
	}

	// Build masquerade config
	if c.Masquerade != nil {
		config.Masquerade = &hysteria2.Masquerade{
			Type:         c.Masquerade.Type,
			SimpleConfig: c.Masquerade.SimpleConfig,
			Directory:    c.Masquerade.Directory,
			Url:          c.Masquerade.URL,
			RewriteHost:  c.Masquerade.RewriteHost,
			StatusCode:   c.Masquerade.StatusCode,
			Headers:      c.Masquerade.Headers,
			Content:      c.Masquerade.Content,
		}

		// Validate masquerade config
		if config.Masquerade.Type != "" {
			switch config.Masquerade.Type {
			case "file":
				if config.Masquerade.Directory == "" {
					return nil, errors.New("Hysteria2: masquerade type 'file' requires 'directory'")
				}
			case "proxy":
				if config.Masquerade.Url == "" {
					return nil, errors.New("Hysteria2: masquerade type 'proxy' requires 'url'")
				}
			case "string":
				// Content can be empty
			default:
				return nil, errors.New("Hysteria2: invalid masquerade type, must be 'file', 'proxy', or 'string'")
			}
		}
	}

	return config, nil
}

// Hysteria2ServerTarget is configuration of a single Hysteria2 server
type Hysteria2ServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
}

// Hysteria2ClientConfig is Outbound configuration for Hysteria2
type Hysteria2ClientConfig struct {
	Address  *Address                 `json:"address"`
	Port     uint16                   `json:"port"`
	Level    byte                     `json:"level"`
	Email    string                   `json:"email"`
	Password string                   `json:"password"`
	Servers  []*Hysteria2ServerTarget `json:"servers"`
}

// Build implements Buildable
func (c *Hysteria2ClientConfig) Build() (proto.Message, error) {
	// Support single server or servers array
	if c.Address != nil {
		c.Servers = []*Hysteria2ServerTarget{
			{
				Address:  c.Address,
				Port:     c.Port,
				Level:    c.Level,
				Email:    c.Email,
				Password: c.Password,
			},
		}
	}

	if len(c.Servers) == 0 {
		return nil, errors.New("Hysteria2: no server configured")
	}

	if len(c.Servers) > 1 {
		return nil, errors.New("Hysteria2: multiple servers not supported, use multiple outbounds instead")
	}

	config := &hysteria2.ClientConfig{}

	for _, server := range c.Servers {
		if server.Address == nil {
			return nil, errors.New("Hysteria2: server address is not set")
		}
		if server.Port == 0 {
			return nil, errors.New("Hysteria2: invalid server port")
		}
		if server.Password == "" {
			return nil, errors.New("Hysteria2: password is not specified")
		}

		config.Server = append(config.Server, &protocol.ServerEndpoint{
			Address: server.Address.Build(),
			Port:    uint32(server.Port),
			User: &protocol.User{
				Level: uint32(server.Level),
				Email: server.Email,
				Account: serial.ToTypedMessage(&hysteria2.Account{
					Password: server.Password,
				}),
			},
		})

		break
	}

	return config, nil
}
