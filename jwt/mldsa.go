package jwt

import (
	"crypto/mldsa"
	"errors"
	"io"
)

var (
	SigningMLDSA44 = NewSignMLDSA(mldsa.MLDSA44(), mldsa.MLDSA44SignatureSize, "ML-DSA-44")
	SigningMLDSA65 = NewSignMLDSA(mldsa.MLDSA65(), mldsa.MLDSA65SignatureSize, "ML-DSA-65")
	SigningMLDSA87 = NewSignMLDSA(mldsa.MLDSA87(), mldsa.MLDSA87SignatureSize, "ML-DSA-87")
)

func init() {
	RegisterSigningMethod(SigningMLDSA44.Alg(), func() any {
		return SigningMLDSA44
	})
	RegisterSigningMethod(SigningMLDSA65.Alg(), func() any {
		return SigningMLDSA65
	})
	RegisterSigningMethod(SigningMLDSA87.Alg(), func() any {
		return SigningMLDSA87
	})
}

var (
	ErrSignMLDSAParametersInvalid = errors.New("go-jwt: MLDSA parameters error")
	ErrSignMLDSASignLengthInvalid = errors.New("go-jwt: MLDSA length error")
	ErrSignMLDSAVerifyFail        = errors.New("go-jwt: MLDSA Verify fail")
)

// SignMLDSA implements the MLDSA family of signing methods.
type SignMLDSA struct {
	Name   string
	Params mldsa.Parameters
	Size   int
}

func NewSignMLDSA(params mldsa.Parameters, size int, name string) *SignMLDSA {
	return &SignMLDSA{
		Name:   name,
		Params: params,
		Size:   size,
	}
}

// Signer algo name.
func (s *SignMLDSA) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *SignMLDSA) SignLength() int {
	return s.Size
}

// Sign implements token signing for the Signer.
func (s *SignMLDSA) Sign(random io.Reader, msg []byte, key *mldsa.PrivateKey) ([]byte, error) {
	if s.Params != key.PublicKey().Parameters() {
		return nil, ErrSignMLDSAParametersInvalid
	}

	signed, err := key.Sign(random, msg, nil)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

// Verify implements token verification for the Signer.
func (s *SignMLDSA) Verify(msg []byte, signature []byte, key *mldsa.PublicKey) (bool, error) {
	if s.Params != key.Parameters() {
		return false, ErrSignMLDSAParametersInvalid
	}

	signLength := s.SignLength()
	if len(signature) != signLength {
		return false, ErrSignMLDSASignLengthInvalid
	}

	err := mldsa.Verify(key, msg, signature, nil)
	if err != nil {
		return false, ErrSignMLDSAVerifyFail
	}

	return true, nil
}
