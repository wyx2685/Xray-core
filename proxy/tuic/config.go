package tuic

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Uuid)
	if err != nil {
		return nil, err
	}
	return &MemoryAccount{
		UUID:     id,
		Password: a.Password,
	}, nil
}

type MemoryAccount struct {
	UUID     uuid.UUID
	Password string
}

func (m *MemoryAccount) Equals(another protocol.Account) bool {
	tuicAccount, ok := another.(*MemoryAccount)
	if !ok {
		return false
	}
	return m.UUID.Equals(&tuicAccount.UUID) && m.Password == tuicAccount.Password
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Uuid:     m.UUID.String(),
		Password: m.Password,
	}
}
