package jwt

import (
	"strings"
)

// Token Header data.
type TokenHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// Token represents a JWT Token.
type Token struct {
	raw       string // full token string
	msg       string // token string without signature
	header    []byte
	claims    []byte
	signature []byte
	encoder   IEncoder
}

func NewToken(encoder IEncoder) *Token {
	return &Token{
		encoder: encoder,
	}
}

// Set header raw
func (t *Token) WithHeader(header []byte) {
	t.header = header
}

// Set header with json encode
func (t *Token) SetHeader(header any) error {
	encoded, err := t.encoder.JSONEncode(header)
	if err != nil {
		return err
	}

	t.header = encoded
	return nil
}

// Set claims raw
func (t *Token) WithClaims(claims []byte) {
	t.claims = claims
}

// Set claims with json encode
func (t *Token) SetClaims(claims any) error {
	encoded, err := t.encoder.JSONEncode(claims)
	if err != nil {
		return err
	}

	t.claims = encoded
	return nil
}

// Set signature raw
func (t *Token) WithSignature(signature []byte) {
	t.signature = signature
}

// SignedString creates and returns a complete, signed JWT.
func (t *Token) SignedString() (string, error) {
	return t.signing(true)
}

// SigningString generates the signing string.
func (t *Token) SigningString() (string, error) {
	return t.signing(false)
}

func (t *Token) signing(needSign bool) (string, error) {
	var buf strings.Builder

	header, err := t.encoder.Base64URLEncode(t.header)
	if err != nil {
		return "", err
	}
	buf.WriteString(header)

	claims, err := t.encoder.Base64URLEncode(t.claims)
	if err != nil {
		return "", err
	}
	buf.WriteString(".")
	buf.WriteString(claims)

	if needSign {
		signature, err := t.encoder.Base64URLEncode(t.signature)
		if err != nil {
			return "", err
		}
		buf.WriteString(".")
		buf.WriteString(signature)
	}

	return buf.String(), nil
}

// Parse token string and returns the parsed token.
func (t *Token) Parse(tokenString string) {
	if len(tokenString) == 0 {
		return
	}

	t.raw = tokenString
	t.header = []byte{}
	t.claims = []byte{}
	t.signature = []byte{}

	list := strings.Split(tokenString, ".")
	if len(list) > 0 {
		t.header, _ = t.encoder.Base64URLDecode(list[0])
	}
	if len(list) > 1 {
		t.claims, _ = t.encoder.Base64URLDecode(list[1])
	}
	if len(list) > 2 {
		t.signature, _ = t.encoder.Base64URLDecode(list[2])
	}

	if len(list) > 1 {
		t.msg = strings.Join([]string{list[0], list[1]}, ".")
	} else {
		t.msg = tokenString
	}
}

// return token raw
func (t *Token) GetRaw() string {
	return t.raw
}

// return token without signature
func (t *Token) GetMsg() string {
	return t.msg
}

// return token string part count
func (t *Token) GetPartCount() int {
	return len(strings.Split(t.raw, "."))
}

// return token TokenHeader struct
func (t *Token) GetHeader() (TokenHeader, error) {
	var parsedHeader map[string]any
	err := t.encoder.JSONDecode(t.header, &parsedHeader)
	if err != nil {
		return TokenHeader{}, err
	}

	var typ = ""
	if val, ok := parsedHeader["typ"]; ok {
		if typVal, ok := val.(string); ok {
			typ = typVal
		}
	}

	var alg = ""
	if val, ok := parsedHeader["alg"]; ok {
		if algVal, ok := val.(string); ok {
			alg = algVal
		}
	}

	var kid = ""
	if val, ok := parsedHeader["kid"]; ok {
		if kidVal, ok := val.(string); ok {
			kid = kidVal
		}
	}

	return TokenHeader{
		Typ: typ,
		Alg: alg,
		Kid: kid,
	}, nil
}

// return token header map
func (t *Token) GetHeaders() (map[string]any, error) {
	var dst map[string]any
	err := t.encoder.JSONDecode(t.header, &dst)
	if err != nil {
		return map[string]any{}, err
	}

	return dst, nil
}

// return token header with custom type
func (t *Token) GetHeadersT(dst any) error {
	return t.encoder.JSONDecode(t.header, dst)
}

// return token claims map
func (t *Token) GetClaims() (MapClaims, error) {
	var dst MapClaims
	err := t.encoder.JSONDecode(t.claims, &dst)
	if err != nil {
		return map[string]any{}, err
	}

	return dst, nil
}

// return token claims with custom type
func (t *Token) GetClaimsT(dst any) error {
	return t.encoder.JSONDecode(t.claims, dst)
}

// return token signature
func (t *Token) GetSignature() []byte {
	return t.signature
}
