package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const MaxModulusLen = 512

var (
	SigningRS256 = NewSignRSA(crypto.SHA256, "RS256")
	SigningRS384 = NewSignRSA(crypto.SHA384, "RS384")
	SigningRS512 = NewSignRSA(crypto.SHA512, "RS512")
)

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

func (s *SignRSA) Alg() string {
	return s.Name
}

// rsa sign size can get from rsa.PrivateKey.Size()
func (s *SignRSA) SignLength() int {
	return MaxModulusLen
}

func (s *SignRSA) Sign(msg []byte, key *rsa.PrivateKey) ([]byte, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, s.Hash, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	return sigBytes, nil
}

func (s *SignRSA) Verify(msg []byte, signature []byte, key *rsa.PublicKey) (bool, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	err := rsa.VerifyPKCS1v15(key, s.Hash, hasher.Sum(nil), signature)
	if err != nil {
		return false, err
	}

	return true, nil
}
