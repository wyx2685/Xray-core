package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

// AnyTLSUser is a single user entry
// For ANYTLS, only password is required; level/email optional.
type AnyTLSUser struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type AnyTLSServerConfig struct {
	Users []*AnyTLSUser `json:"users"`
	// Easier authoring: accept padding scheme as lines and join internally
	PaddingScheme []string `json:"paddingScheme"`
}

func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	cfg := &anytls.ServerConfig{
		Users: make([]*protocol.User, 0, len(c.Users)),
	}
	if len(c.PaddingScheme) > 0 {
		cfg.PaddingScheme = strings.Join(c.PaddingScheme, "\n")
	}
	for _, u := range c.Users {
		if u.Password == "" {
			return nil, errors.New("ANYTLS: user password required")
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&anytls.Account{
				Password: u.Password,
			}),
		})
	}
	return cfg, nil
}

type AnyTLSClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Level    uint32   `json:"level"`
}

func (c *AnyTLSClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("ANYTLS: server address is required")
	}
	if c.Password == "" {
		return nil, errors.New("ANYTLS: password is required")
	}

	cfg := &anytls.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&anytls.Account{
					Password: c.Password,
				}),
			},
		},
	}

	return cfg, nil
}
