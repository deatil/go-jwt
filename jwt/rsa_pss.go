package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

var (
	SigningPS256 = NewSignRSAPss(crypto.SHA256, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}, "PS256")

	SigningPS384 = NewSignRSAPss(crypto.SHA384, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}, "PS384")

	SigningPS512 = NewSignRSAPss(crypto.SHA512, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}, "PS512")
)

type SignRSAPss struct {
	Name string
	Hash crypto.Hash

	Options       *rsa.PSSOptions
	VerifyOptions *rsa.PSSOptions
}

func NewSignRSAPss(
	hash crypto.Hash,
	Options *rsa.PSSOptions,
	VerifyOptions *rsa.PSSOptions,
	name string,
) *SignRSAPss {
	return &SignRSAPss{
		Name: name,
		Hash: hash,
	}
}

func (s *SignRSAPss) Alg() string {
	return s.Name
}

func (s *SignRSAPss) SignLength() int {
	return MaxModulusLen
}

func (s *SignRSAPss) Sign(msg []byte, key *rsa.PrivateKey) ([]byte, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	sigBytes, err := rsa.SignPSS(rand.Reader, key, s.Hash, hasher.Sum(nil), s.Options)
	if err != nil {
		return nil, err
	}

	return sigBytes, nil
}

func (s *SignRSAPss) Verify(msg []byte, signature []byte, key *rsa.PublicKey) (bool, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	opts := s.Options
	if s.VerifyOptions != nil {
		opts = s.VerifyOptions
	}

	err := rsa.VerifyPSS(key, s.Hash, hasher.Sum(nil), signature, opts)
	if err != nil {
		return false, err
	}

	return true, nil
}
