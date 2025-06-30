package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

var (
	SigningRS256 = NewSignRSA(crypto.SHA256, "RS256")
	SigningRS384 = NewSignRSA(crypto.SHA384, "RS384")
	SigningRS512 = NewSignRSA(crypto.SHA512, "RS512")
)

func init() {
	RegisterSigningMethod(SigningRS256.Alg(), func() any {
		return SigningRS256
	})
	RegisterSigningMethod(SigningRS384.Alg(), func() any {
		return SigningRS384
	})
	RegisterSigningMethod(SigningRS512.Alg(), func() any {
		return SigningRS512
	})
}

const MaxModulusLen = 512

// SignRSA implements the RSA family of signing methods.
type SignRSA struct {
	Name string
	Hash crypto.Hash
}

func NewSignRSA(hash crypto.Hash, name string) *SignRSA {
	return &SignRSA{
		Name: name,
		Hash: hash,
	}
}

// Signer algo name.
func (s *SignRSA) Alg() string {
	return s.Name
}

// Signer signed bytes length.
// rsa sign size can get from rsa.PrivateKey.Size()
func (s *SignRSA) SignLength() int {
	return MaxModulusLen
}

// Sign implements token signing for the Signer.
func (s *SignRSA) Sign(msg []byte, key *rsa.PrivateKey) ([]byte, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, s.Hash, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	return sigBytes, nil
}

// Verify implements token verification for the Signer.
func (s *SignRSA) Verify(msg []byte, signature []byte, key *rsa.PublicKey) (bool, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	err := rsa.VerifyPKCS1v15(key, s.Hash, hasher.Sum(nil), signature)
	if err != nil {
		return false, err
	}

	return true, nil
}
