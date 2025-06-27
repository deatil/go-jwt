package jwt

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
)

type JoseEncoder struct{}

func NewJoseEncoder() *JoseEncoder {
	return &JoseEncoder{}
}

func (j *JoseEncoder) Base64URLEncode(data []byte) (string, error) {
	buffer := base64.RawURLEncoding.EncodeToString(data)
	return buffer, nil
}

func (j *JoseEncoder) Base64URLDecode(data string) ([]byte, error) {
	buffer, err := base64.RawURLEncoding.DecodeString(data)
	return buffer, err
}

func (j *JoseEncoder) JSONEncode(data any) ([]byte, error) {
	buffer, err := json.Marshal(data)
	return buffer, err
}

func (j *JoseEncoder) JSONDecode(data []byte, dst any) error {
	err := json.Unmarshal(data, dst)
	return err
}

var ErrPEMInvalid = errors.New("go-jwt: PEM encoded invalid")

func ParsePEM(data []byte) ([]byte, error) {
	var block *pem.Block
	if block, _ = pem.Decode(data); block == nil {
		return nil, ErrPEMInvalid
	}

	return block.Bytes, nil
}
