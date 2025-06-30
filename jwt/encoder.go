package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// default encoder for jwt
var JWTEncoder = NewJoseEncoder()

type JoseEncoder struct{}

func NewJoseEncoder() *JoseEncoder {
	return &JoseEncoder{}
}

func (j *JoseEncoder) Base64URLEncode(data []byte) (string, error) {
	buffer := base64.RawURLEncoding.EncodeToString(data)
	return buffer, nil
}

func (j *JoseEncoder) Base64URLDecode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

func (j *JoseEncoder) JSONEncode(data any) ([]byte, error) {
	return json.Marshal(data)
}

func (j *JoseEncoder) JSONDecode(data []byte, dst any) error {
	return json.Unmarshal(data, dst)
}
