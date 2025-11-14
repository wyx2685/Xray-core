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

// Hysteria2ClientConfig is Outbound configuration for Hysteria2
type Hysteria2ClientConfig struct {
	Address     *Address             `json:"address"`
	Port        uint16               `json:"port"`
	Ports       []string             `json:"ports"`
	Password    string               `json:"password"`
	Email       string               `json:"email"`
	Level       byte                 `json:"level"`
	UpMbps      uint64               `json:"up_mbps"`
	DownMbps    uint64               `json:"down_mbps"`
	HopInterval string               `json:"hop_interval"`
	Obfs        *Hysteria2ObfsConfig `json:"obfs"`
}

// Build implements Buildable
func (c *Hysteria2ClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("Hysteria2: server address is not set")
	}

	// If ports is set, use it; otherwise fall back to port
	if len(c.Ports) == 0 && c.Port == 0 {
		return nil, errors.New("Hysteria2: either ports or port must be specified")
	}

	if c.Password == "" {
		return nil, errors.New("Hysteria2: password is not specified")
	}

	// Set default hop_interval if ports is used and hop_interval is empty
	hopInterval := c.HopInterval
	if len(c.Ports) > 0 && hopInterval == "" {
		hopInterval = "30s"
	}

	// When using ports for port hopping, port field is still required for UDP socket creation
	// If not specified, use default port 443 (standard HTTPS/QUIC port)
	port := c.Port
	if len(c.Ports) > 0 && port == 0 {
		port = 443
	}

	config := &hysteria2.ClientConfig{
		UpMbps:      c.UpMbps,
		DownMbps:    c.DownMbps,
		HopInterval: hopInterval,
		ServerPorts: c.Ports,
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

	config.Server = &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(port),
		User: &protocol.User{
			Level: uint32(c.Level),
			Email: c.Email,
			Account: serial.ToTypedMessage(&hysteria2.Account{
				Password: c.Password,
			}),
		},
	}

	return config, nil
}
