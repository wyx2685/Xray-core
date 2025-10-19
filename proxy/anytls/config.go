package anytls

import (
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount holds resolved account for ANYTLS
// Only a password string is needed; sha256 is computed per connection for auth

type MemoryAccount struct {
	Password string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{Password: a.Password}, nil
}

func (m *MemoryAccount) Equals(another protocol.Account) bool {
	if o, ok := another.(*MemoryAccount); ok {
		return m.Password == o.Password
	}
	return false
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{Password: m.Password}
}
