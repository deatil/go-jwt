package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	"github.com/deatil/go-jwt/encoder"
)

const Version = "1.0.10021"

var (
	// Hmac
	SigningMethodHMD5  = NewJWT[[]byte, []byte](SigningHMD5, JWTEncoder)
	SigningMethodHSHA1 = NewJWT[[]byte, []byte](SigningHSHA1, JWTEncoder)
	SigningMethodHS224 = NewJWT[[]byte, []byte](SigningHS224, JWTEncoder)
	SigningMethodHS256 = NewJWT[[]byte, []byte](SigningHS256, JWTEncoder)
	SigningMethodHS384 = NewJWT[[]byte, []byte](SigningHS384, JWTEncoder)
	SigningMethodHS512 = NewJWT[[]byte, []byte](SigningHS512, JWTEncoder)

	// RSA
	SigningMethodRS256 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS256, JWTEncoder)
	SigningMethodRS384 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS384, JWTEncoder)
	SigningMethodRS512 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS512, JWTEncoder)

	// RSA-PSS
	SigningMethodPS256 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS256, JWTEncoder)
	SigningMethodPS384 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS384, JWTEncoder)
	SigningMethodPS512 = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningPS512, JWTEncoder)

	// ECDSA
	SigningMethodES256 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES256, JWTEncoder)
	SigningMethodES384 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES384, JWTEncoder)
	SigningMethodES512 = NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES512, JWTEncoder)

	// EdDSA
	SigningMethodEdDSA   = NewJWT[ed25519.PrivateKey, ed25519.PublicKey](SigningEdDSA, JWTEncoder)
	SigningMethodED25519 = NewJWT[ed25519.PrivateKey, ed25519.PublicKey](SigningED25519, JWTEncoder)

	// Blake2b
	SigningMethodBLAKE2B = NewJWT[[]byte, []byte](SigningBLAKE2B, JWTEncoder)

	// None
	SigningMethodNone = NewJWT[[]byte, []byte](SigningNone, JWTEncoder)
)

const (
	// Defines the list of headers that are registered in the IANA "JSON Web Token Headers" registry
	RegisteredHeadersType       = "typ"
	RegisteredHeadersAlgorithm  = "alg"
	RegisteredHeadersEncryption = "enc"

	// Defines the list of claims that are registered in the IANA "JSON Web Token Claims" registry
	RegisteredClaimsAudience       = "aud"
	RegisteredClaimsExpirationTime = "exp"
	RegisteredClaimsID             = "jti"
	RegisteredClaimsIssuedAt       = "iat"
	RegisteredClaimsIssuer         = "iss"
	RegisteredClaimsNotBefore      = "nbf"
	RegisteredClaimsSubject        = "sub"
)

var (
	ErrJWTInvalidType           = errors.New("go-jwt: invalid type for claim")
	ErrJWTSignerInvalid         = errors.New("go-jwt: Signer invalid")
	ErrJWTEncoderInvalid        = errors.New("go-jwt: Encoder invalid")
	ErrJWTTokenInvalid          = errors.New("go-jwt: Token invalid")
	ErrJWTTypeInvalid           = errors.New("go-jwt: Type invalid")
	ErrJWTAlgoInvalid           = errors.New("go-jwt: Algo invalid")
	ErrJWTTokenSignatureInvalid = errors.New("go-jwt: token signature is invalid")
	ErrJWTMethodExists          = errors.New("go-jwt: Method not exists")
	ErrJWTMethodInvalid         = errors.New("go-jwt: Method invalid")
	ErrJWTVerifyFail            = errors.New("go-jwt: Verify fail")
)

// jwt default encoder
var JWTEncoder = encoder.NewJoseEncoder()

// jwt encoder for strict decoding
var JWTStrictEncoder = encoder.NewJoseEncoder(encoder.WithStrictDecoding())

// jwt sing algo interface
type ISignAlgo interface {
	// algo name
	Alg() string

	// sign length
	SignLength() int
}

// jwt singing driver interface
type ISigning[S any] interface {
	ISignAlgo

	// sign function
	Sign(msg []byte, signKey S) ([]byte, error)
}

// jwt verifying driver interface
type IVerifying[V any] interface {
	ISignAlgo

	// verify function
	Verify(msg []byte, signature []byte, verifyKey V) (bool, error)
}

// jwt singer driver interface
type ISigner[S any, V any] interface {
	ISignAlgo

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

type JWT[S any, V any] struct {
	signer  ISigner[S, V]
	encoder IEncoder
}

func NewJWT[S any, V any](signer ISigner[S, V], encoder IEncoder) JWT[S, V] {
	if signer == nil {
		panic(ErrJWTSignerInvalid)
	}
	if encoder == nil {
		panic(ErrJWTEncoderInvalid)
	}

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

// with new encoder
func (jwt *JWT[S, V]) WithEncoder(encoder IEncoder) *JWT[S, V] {
	jwt.encoder = encoder
	return jwt
}

// Signer algo name.
func (jwt *JWT[S, V]) Alg() string {
	return jwt.signer.Alg()
}

// Signer signed bytes length.
func (jwt *JWT[S, V]) SignLength() int {
	return jwt.signer.SignLength()
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

	if t.GetPartCount() < 2 {
		return nil, ErrJWTTokenInvalid
	}

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
	signingString := t.GetMsg()

	ok, _ := jwt.signer.Verify([]byte(signingString), signature, verifyKey)
	if !ok {
		return nil, ErrJWTVerifyFail
	}

	return t, nil
}

// return a new *Builder.
func (jwt *JWT[S, V]) Build() *Builder[S] {
	return NewBuilder[S](jwt.signer, jwt.encoder)
}

// get token header from token string
func GetTokenHeader(tokenString string, encoder ...IEncoder) (TokenHeader, error) {
	var useEncoder IEncoder
	if len(encoder) > 0 {
		useEncoder = encoder[0]
	} else {
		useEncoder = JWTEncoder
	}

	var t = NewToken(useEncoder)
	t.Parse(tokenString)

	return t.GetHeader()
}
