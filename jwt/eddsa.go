package jwt

import (
	"crypto/ed25519"
	"errors"
)

var (
	SigningEdDSA   = NewSignEdDSA("EdDSA")
	SigningED25519 = NewSignEdDSA("ED25519")
)

func init() {
	RegisterSigningMethod(SigningEdDSA.Alg(), func() any {
		return SigningEdDSA
	})
	RegisterSigningMethod(SigningED25519.Alg(), func() any {
		return SigningED25519
	})
}

var (
	ErrSignEdDSASignLengthInvalid = errors.New("go-jwt: sign length error")
	ErrSignEdDSAVerifyFail        = errors.New("go-jwt: SignEdDSA Verify fail")
)

// SignEdDSA implements the EdDSA family of signing methods.
type SignEdDSA struct {
	Name string
}

func NewSignEdDSA(name string) *SignEdDSA {
	return &SignEdDSA{
		Name: name,
	}
}

// Signer algo name.
func (s *SignEdDSA) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *SignEdDSA) SignLength() int {
	return ed25519.SignatureSize
}

// Sign implements token signing for the Signer.
func (s *SignEdDSA) Sign(msg []byte, key ed25519.PrivateKey) ([]byte, error) {
	signed := ed25519.Sign(key, msg)

	return signed, nil
}

// Verify implements token verification for the Signer.
func (s *SignEdDSA) Verify(msg []byte, signature []byte, key ed25519.PublicKey) (bool, error) {
	signLength := s.SignLength()
	if len(signature) != signLength {
		return false, ErrSignEdDSASignLengthInvalid
	}

	verifyStatus := ed25519.Verify(key, msg, signature)
	if !verifyStatus {
		return false, ErrSignEdDSAVerifyFail
	}

	return true, nil
}
