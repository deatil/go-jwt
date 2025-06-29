package jwt

import (
	"errors"
)

var (
	SigningNone = NewSignNone("none")
)

func init() {
	RegisterSigningMethod(SigningNone.Alg(), func() any {
		return SigningNone
	})
}

var ErrSignNoneSignatureInvalid = errors.New("go-jwt: SignNone verify signature not empty")

// SignNone implements signing methods.
type SignNone struct {
	Name string
}

func NewSignNone(name string) *SignNone {
	return &SignNone{
		Name: name,
	}
}

// Signer algo name.
func (s *SignNone) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *SignNone) SignLength() int {
	return 0
}

// Sign implements token signing for the Signer.
func (s *SignNone) Sign(msg []byte, key []byte) ([]byte, error) {
	return nil, nil
}

// Verify implements token verification for the Signer.
func (s *SignNone) Verify(msg []byte, signature []byte, key []byte) (bool, error) {
	if len(signature) > 0 {
		return false, ErrSignNoneSignatureInvalid
	}

	return true, nil
}
