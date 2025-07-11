package jwt

import (
	"encoding/pem"
	"errors"
)

var ErrPEMInvalid = errors.New("go-jwt: PEM parse invalid")

// parse PEM string and return der bytes
func ParsePEM(data []byte) ([]byte, error) {
	var block *pem.Block
	if block, _ = pem.Decode(data); block == nil {
		return nil, ErrPEMInvalid
	}

	return block.Bytes, nil
}
