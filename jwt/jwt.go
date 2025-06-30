package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
)

var (
	// Hmac
	SigningMethodHMD5  = NewJWT[[]byte, []byte](SigningHMD5, NewJoseEncoder())
	SigningMethodHSHA1 = NewJWT[[]byte, []byte](SigningHSHA1, NewJoseEncoder())
	SigningMethodHS224 = NewJWT[[]byte, []byte](SigningHS224, NewJoseEncoder())
	SigningMethodHS256 = NewJWT[[]byte, []byte](SigningHS256, NewJoseEncoder())
	SigningMethodHS384 = NewJWT[[]byte, []byte](SigningHS384, NewJoseEncoder())
	SigningMethodHS512 = NewJWT[[]byte, []byte](SigningHS512, NewJoseEncoder())

	// RSA
	SigningMethodRS256 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS256, NewJoseEncoder())
	SigningMethodRS384 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS384, NewJoseEncoder())
	SigningMethodRS512 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS512, NewJoseEncoder())

	// RSA-PSS
	SigningMethodPS256 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS256, NewJoseEncoder())
	SigningMethodPS384 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS384, NewJoseEncoder())
	SigningMethodPS512 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS512, NewJoseEncoder())

	// ECDSA
	SigningMethodES256 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES256, NewJoseEncoder())
	SigningMethodES384 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES384, NewJoseEncoder())
	SigningMethodES512 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES512, NewJoseEncoder())

	// EdDSA
	SigningMethodEdDSA   = NewJWT[ed25519.PrivateKey, ed25519.PublicKey](SigningEdDSA, NewJoseEncoder())
	SigningMethodED25519 = NewJWT[ed25519.PrivateKey, ed25519.PublicKey](SigningED25519, NewJoseEncoder())

	// Blake2b
	SigningMethodBLAKE2B = NewJWT[[]byte, []byte](SigningBLAKE2B, NewJoseEncoder())

	// None
	SigningMethodNone = NewJWT[[]byte, []byte](SigningNone, NewJoseEncoder())
)

var (
	ErrJWTTypeInvalid   = errors.New("go-jwt: Type invalid")
	ErrJWTAlgoInvalid   = errors.New("go-jwt: Algo invalid")
	ErrJWTMethodInvalid = errors.New("go-jwt: Method invalid")
	ErrJWTVerifyFail    = errors.New("go-jwt: Verify fail")
)

// jwt singer driver interface
type ISigner[S any, V any] interface {
	// algo name
	Alg() string

	// sign length
	SignLength() int

	// sign function
	Sign(msg []byte, signKey S) ([]byte, error)

	// verify function
	Verify(msg []byte, signature []byte, verifyKey V) (bool, error)
}

// jwt encoder driver interface
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

const (
	// Defines the list of claims that are registered in the IANA "JSON Web Token Claims" registry
	RegisteredClaimsAudience       = "aud"
	RegisteredClaimsExpirationTime = "exp"
	RegisteredClaimsID             = "jti"
	RegisteredClaimsIssuedAt       = "iat"
	RegisteredClaimsIssuer         = "iss"
	RegisteredClaimsNotBefore      = "nbf"
	RegisteredClaimsSubject        = "sub"

	// Defines the list of headers that are registered in the IANA "JSON Web Token Headers" registry
	RegisteredHeadersType       = "typ"
	RegisteredHeadersAlgorithm  = "alg"
	RegisteredHeadersEncryption = "enc"
)

type JWTClaims struct {
	Issuer    string `json:"iss,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Expiry    int64  `json:"exp,omitempty"` // Expiration Time
	Audience  string `json:"aud,omitempty"`
	Subject   string `json:"sub,omitempty"`
	ID        string `json:"jti,omitempty"` // JWT ID
	NotBefore int64  `json:"bnf,omitempty"` // Not Before
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

// return a clone JWT
func (jwt JWT[S, V]) New() *JWT[S, V] {
	return &JWT[S, V]{
		signer:  jwt.signer,
		encoder: jwt.encoder,
	}
}

// Signer algo name.
func (jwt *JWT[S, V]) Alg() string {
	return jwt.signer.Alg()
}

// Signer signed bytes length.
func (jwt *JWT[S, V]) SignLength() int {
	return jwt.signer.SignLength()
}

// with new encoder
func (jwt *JWT[S, V]) WithEncoder(encoder IEncoder) *JWT[S, V] {
	jwt.encoder = encoder
	return jwt
}

// Sign implements token signing for the Signer.
func (jwt *JWT[S, V]) Sign(claims any, signKey S) (string, error) {
	header := TokenHeader{
		Typ: "JWT",
		Alg: jwt.signer.Alg(),
	}

	return jwt.SignWithHeader(header, claims, signKey)
}

// SignWithHeader implements token signing for the Signer.
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

// Parse parses the signature and returns the parsed token.
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

	ok, _ := jwt.signer.Verify([]byte(signingString), signature, verifyKey)
	if !ok {
		return nil, ErrJWTVerifyFail
	}

	return t, nil
}

// Parse parses the signature and returns the parsed token.
func Parse[S any, V any](tokenString string, key V, encoder ...IEncoder) (*Token, error) {
	var defaultEncoder IEncoder = NewJoseEncoder()
	if len(encoder) > 0 {
		defaultEncoder = encoder[0]
	}

	t := NewToken(defaultEncoder)
	t.Parse(tokenString)

	header, err := t.GetHeader()
	if err != nil {
		return nil, err
	}

	if len(header.Typ) > 0 && header.Typ != "JWT" {
		return nil, ErrJWTTypeInvalid
	}

	signer := GetSigningMethod[S, V](header.Alg)
	if signer == nil {
		return nil, ErrJWTMethodInvalid
	}

	signature := t.GetSignature()

	signingString, err := t.SigningString()
	if err != nil {
		return nil, err
	}

	ok, _ := signer.Verify([]byte(signingString), signature, key)
	if !ok {
		return nil, ErrJWTVerifyFail
	}

	return t, nil
}

// get token header from token string
func GetTokenHeader(tokenString string, encoder ...IEncoder) (TokenHeader, error) {
	var defaultEncoder IEncoder = NewJoseEncoder()
	if len(encoder) > 0 {
		defaultEncoder = encoder[0]
	}

	var t = NewToken(defaultEncoder)
	t.Parse(tokenString)

	return t.GetHeader()
}
