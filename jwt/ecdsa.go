package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	SigningES256 = NewSignECDSA(crypto.SHA256, 32, "ES256")
	SigningES384 = NewSignECDSA(crypto.SHA384, 48, "ES384")
	SigningES512 = NewSignECDSA(crypto.SHA512, 66, "ES512")
)

func init() {
	RegisterSigningMethod(SigningES256.Alg(), func() any {
		return SigningES256
	})
	RegisterSigningMethod(SigningES384.Alg(), func() any {
		return SigningES384
	})
	RegisterSigningMethod(SigningES512.Alg(), func() any {
		return SigningES512
	})
}

var (
	ErrSignECDSASignLengthInvalid = errors.New("go-jwt: sign length error")
	ErrSignECDSAVerifyFail        = errors.New("go-jwt: SignECDSA Verify fail")
)

// SignECDSA implements the ECDSA family of signing methods.
type SignECDSA struct {
	Name    string
	Hash    crypto.Hash
	KeySize int
}

func NewSignECDSA(hash crypto.Hash, keySize int, name string) *SignECDSA {
	return &SignECDSA{
		Name:    name,
		Hash:    hash,
		KeySize: keySize,
	}
}

// Signer algo name.
func (s *SignECDSA) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *SignECDSA) SignLength() int {
	return 2 * s.KeySize
}

// Sign implements token signing for the Signer.
func (s *SignECDSA) Sign(msg []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	rr, ss, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	keyBytes := s.KeySize

	signed := make([]byte, 2*keyBytes)
	rr.FillBytes(signed[0:keyBytes])
	ss.FillBytes(signed[keyBytes:])

	return signed, nil
}

// Verify implements token verification for the Signer.
func (s *SignECDSA) Verify(msg []byte, signature []byte, key *ecdsa.PublicKey) (bool, error) {
	signLength := s.SignLength()
	if len(signature) != signLength {
		return false, ErrSignECDSASignLengthInvalid
	}

	rr := big.NewInt(0).SetBytes(signature[:s.KeySize])
	ss := big.NewInt(0).SetBytes(signature[s.KeySize:])

	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	verifyStatus := ecdsa.Verify(key, hasher.Sum(nil), rr, ss)
	if !verifyStatus {
		return false, ErrSignECDSAVerifyFail
	}

	return true, nil
}
