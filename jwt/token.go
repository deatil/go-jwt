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
	raw       string
	header    []byte
	claims    []byte
	signature []byte

	encoder IEncoder
}

func NewToken(encoder IEncoder) *Token {
	return &Token{
		encoder: encoder,
	}
}

func (t *Token) WithHeader(header []byte) {
	t.header = header
}

// Set header for json encode
func (t *Token) SetHeader(header any) error {
	encoded, err := t.encoder.JSONEncode(header)
	if err != nil {
		return err
	}

	t.header = encoded
	return nil
}

func (t *Token) WithClaims(claims []byte) {
	t.claims = claims
}

// Set claims for json encode
func (t *Token) SetClaims(claims any) error {
	encoded, err := t.encoder.JSONEncode(claims)
	if err != nil {
		return err
	}

	t.claims = encoded
	return nil
}

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
	t.header = []byte("")
	t.claims = []byte("")
	t.signature = []byte("")

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
}

func (t *Token) GetRaw() string {
	return t.raw
}

func (t *Token) GetRawNoSignature() string {
	count := strings.Count(t.raw, ".")
	if count <= 1 {
		return t.raw
	}

	var header = ""
	var claims = ""

	list := strings.Split(t.raw, ".")
	if len(list) > 0 {
		header = list[0]
	}
	if len(list) > 1 {
		claims = list[1]
	}

	return strings.Join([]string{header, claims}, ".")
}

func (t *Token) GetHeader() (TokenHeader, error) {
	var parsedHeader map[string]any
	err := t.encoder.JSONDecode(t.header, &parsedHeader)
	if err != nil {
		return TokenHeader{}, err
	}

	var typ = ""
	if val, ok := parsedHeader["typ"]; ok {
		if typVal, ok2 := val.(string); ok2 {
			typ = typVal
		}
	}

	var alg = ""
	if val, ok := parsedHeader["alg"]; ok {
		if algVal, ok2 := val.(string); ok2 {
			alg = algVal
		}
	}

	var kid = ""
	if val, ok := parsedHeader["kid"]; ok {
		if kidVal, ok2 := val.(string); ok2 {
			kid = kidVal
		}
	}

	return TokenHeader{
		Typ: typ,
		Alg: alg,
		Kid: kid,
	}, nil
}

func (t *Token) GetHeaders() (map[string]any, error) {
	var dst map[string]any
	err := t.encoder.JSONDecode(t.header, &dst)
	if err != nil {
		return map[string]any{}, err
	}

	return dst, nil
}

func (t *Token) GetHeadersT(dst any) error {
	return t.encoder.JSONDecode(t.header, dst)
}

func (t *Token) GetClaims() (map[string]any, error) {
	var dst map[string]any
	err := t.encoder.JSONDecode(t.claims, &dst)
	if err != nil {
		return map[string]any{}, err
	}

	return dst, nil
}

func (t *Token) GetClaimsT(dst any) error {
	return t.encoder.JSONDecode(t.claims, dst)
}

func (t *Token) GetSignature() []byte {
	return t.signature
}
