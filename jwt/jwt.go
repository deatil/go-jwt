package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
)

var (
	SigningMethodHMD5  = NewJWT[[]byte, []byte](SigningHMD5, NewJoseEncoder())
	SigningMethodHSHA1 = NewJWT[[]byte, []byte](SigningHSHA1, NewJoseEncoder())
	SigningMethodHS224 = NewJWT[[]byte, []byte](SigningHS224, NewJoseEncoder())
	SigningMethodHS256 = NewJWT[[]byte, []byte](SigningHS256, NewJoseEncoder())
	SigningMethodHS384 = NewJWT[[]byte, []byte](SigningHS384, NewJoseEncoder())
	SigningMethodHS512 = NewJWT[[]byte, []byte](SigningHS512, NewJoseEncoder())

	SigningMethodRS256 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS256, NewJoseEncoder())
	SigningMethodRS384 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS384, NewJoseEncoder())
	SigningMethodRS512 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS512, NewJoseEncoder())

	SigningMethodPS256 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS256, NewJoseEncoder())
	SigningMethodPS384 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS384, NewJoseEncoder())
	SigningMethodPS512 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS512, NewJoseEncoder())

	SigningMethodES256 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES256, NewJoseEncoder())
	SigningMethodES384 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES384, NewJoseEncoder())
	SigningMethodES512 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES512, NewJoseEncoder())

	SigningMethodEdDSA   = NewJWT[ed25519.PrivateKey, ed25519.PublicKey](SigningEdDSA, NewJoseEncoder())
	SigningMethodED25519 = NewJWT[ed25519.PrivateKey, ed25519.PublicKey](SigningED25519, NewJoseEncoder())

	SigningMethodBLAKE2B = NewJWT[[]byte, []byte](SigningBLAKE2B, NewJoseEncoder())

	SigningMethodNone = NewJWT[[]byte, []byte](SigningNone, NewJoseEncoder())
)

var (
	ErrJWTTypeInvalid = errors.New("go-jwt: Type invalid")
	ErrJWTAlgoInvalid = errors.New("go-jwt: Algo invalid")
	ErrJWTVerifyFail  = errors.New("go-jwt: Verify fail")
)

type ISigner[S any, V any] interface {
	// algo name
	Alg() string

	// sign length
	SignLength() int

	// sign function
	Sign(msg []byte, key S) ([]byte, error)

	// verify function
	Verify(msg []byte, signature []byte, key V) (bool, error)
}

type IEncoder interface {
	// Base64URL Encode function
	Base64URLEncode(data []byte) (string, error)

	// Base64URL Decode function
	Base64URLDecode(data string) ([]byte, error)

	// JSON Encode function
	JSONEncode(data any) ([]byte, error)

	// JSON Decode function
	JSONDecode(data []byte, dst any) error
}

type JWTClaims struct {
	// Issuer
	Iss string `json:"iss,omitempty"`
	// Issued At
	Iat int64 `json:"iat,omitempty"`
	// Expiration Time
	Exp int64 `json:"exp,omitempty"`
	// Audience
	Aud string `json:"aud,omitempty"`
	// Subject
	Sub string `json:"sub,omitempty"`
	// JWT ID
	Jti string `json:"jti,omitempty"`
	// Not Before
	Nbf int64 `json:"bnf,omitempty"`
}

type JWT[S any, V any] struct {
	signer  ISigner[S, V]
	encoder IEncoder
}

func NewJWT[S any, V any](signer ISigner[S, V], encoder IEncoder) JWT[S, V] {
	return JWT[S, V]{
		signer:  signer,
		encoder: encoder,
	}
}

func (jwt JWT[S, V]) New() *JWT[S, V] {
	return &JWT[S, V]{
		signer:  jwt.signer,
		encoder: jwt.encoder,
	}
}

func (jwt *JWT[S, V]) Alg() string {
	return jwt.signer.Alg()
}

func (jwt *JWT[S, V]) SignLength() int {
	return jwt.signer.SignLength()
}

func (jwt *JWT[S, V]) WithEncoder(encoder IEncoder) *JWT[S, V] {
	jwt.encoder = encoder
	return jwt
}

func (jwt *JWT[S, V]) Sign(claims any, signKey S) (string, error) {
	header := TokenHeader{
		Typ: "JWT",
		Alg: jwt.signer.Alg(),
	}

	return jwt.SignWithHeader(header, claims, signKey)
}

func (jwt *JWT[S, V]) SignWithHeader(header any, claims any, signKey S) (string, error) {
	t := NewToken(jwt.encoder)
	t.SetHeader(header)
	t.SetClaims(claims)

	signingString, err := t.SigningString()
	if err != nil {
		return "", err
	}

	signature, err := jwt.signer.Sign([]byte(signingString), signKey)
	if err != nil {
		return "", err
	}

	t.WithSignature(signature)

	return t.SignedString()
}

func (jwt *JWT[S, V]) Parse(tokenString string, verifyKey V) (*Token, error) {
	t := NewToken(jwt.encoder)
	t.Parse(tokenString)

	header, err := t.GetHeader()
	if err != nil {
		return nil, err
	}

	if len(header.Typ) > 0 && header.Typ != "JWT" {
		return nil, ErrJWTTypeInvalid
	}

	if header.Alg != jwt.signer.Alg() {
		return nil, ErrJWTAlgoInvalid
	}

	signature := t.GetSignature()

	signingString, err := t.SigningString()
	if err != nil {
		return nil, err
	}

	ok, err := jwt.signer.Verify([]byte(signingString), signature, verifyKey)
	if !ok {
		return nil, ErrJWTVerifyFail
	}

	return t, nil
}

func GetTokenHeader(tokenString string, encoder ...IEncoder) (TokenHeader, error) {
	var defaultEncoder IEncoder = NewJoseEncoder()
	if len(encoder) > 0 {
		defaultEncoder = encoder[0]
	}

	var t = NewToken(defaultEncoder)
	t.Parse(tokenString)

	return t.GetHeader()
}
