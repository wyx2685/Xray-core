package tuic

import (
	"github.com/xtls/xray-core/common/errors"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

const protocolName = "tuic"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
