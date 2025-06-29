package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

var (
	SigningPS256 = NewSignRSAPSS(crypto.SHA256, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}, "PS256")

	SigningPS384 = NewSignRSAPSS(crypto.SHA384, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}, "PS384")

	SigningPS512 = NewSignRSAPSS(crypto.SHA512, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}, "PS512")
)

func init() {
	RegisterSigningMethod(SigningPS256.Alg(), func() any {
		return SigningPS256
	})
	RegisterSigningMethod(SigningPS384.Alg(), func() any {
		return SigningPS384
	})
	RegisterSigningMethod(SigningPS512.Alg(), func() any {
		return SigningPS512
	})
}

// SignRSA implements the RSA family of signing methods.
type SignRSAPSS struct {
	Name string
	Hash crypto.Hash

	Options       *rsa.PSSOptions
	VerifyOptions *rsa.PSSOptions
}

func NewSignRSAPSS(
	hash crypto.Hash,
	options *rsa.PSSOptions,
	verifyOptions *rsa.PSSOptions,
	name string,
) *SignRSAPSS {
	return &SignRSAPSS{
		Name: name,
		Hash: hash,

		Options:       options,
		VerifyOptions: verifyOptions,
	}
}

// Signer algo name.
func (s *SignRSAPSS) Alg() string {
	return s.Name
}

// Signer signed bytes length.
// rsa sign size can get from rsa.PrivateKey.Size()
func (s *SignRSAPSS) SignLength() int {
	return MaxModulusLen
}

// Sign implements token signing for the Signer.
func (s *SignRSAPSS) Sign(msg []byte, key *rsa.PrivateKey) ([]byte, error) {
	hasher := s.Hash.New()
	hasher.Write([]byte(msg))

	sigBytes, err := rsa.SignPSS(rand.Reader, key, s.Hash, hasher.Sum(nil), s.Options)
	if err != nil {
		return nil, err
	}

	return sigBytes, nil
}

// Verify implements token verification for the Signer.
func (s *SignRSAPSS) Verify(msg []byte, signature []byte, key *rsa.PublicKey) (bool, error) {
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
