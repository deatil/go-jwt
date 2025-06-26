package jwt

import (
    "errors"
    "crypto/ed25519"
)

var (
    SigningEdDSA   = NewSignEdDSA("EdDSA")
    SigningED25519 = NewSignEdDSA("ED25519")
)

type SignEdDSA struct {
    Name string
}

func NewSignEdDSA(name string) *SignEdDSA {
    return &SignEdDSA{
        Name: name,
    }
}

func (s *SignEdDSA) Alg() string {
    return s.Name
}

func (s *SignEdDSA) SignLength() int {
    return ed25519.SignatureSize
}

func (s *SignEdDSA) Sign(msg []byte, key ed25519.PrivateKey) ([]byte, error) {
    signed := ed25519.Sign(key, msg)

    return signed, nil
}

func (s *SignEdDSA) Verify(msg []byte, signature []byte, key ed25519.PublicKey) (bool, error) {
    signLength := s.SignLength()
    if len(signature) != signLength {
        return false, errors.New("go-jwt: sign length error")
    }

    res := ed25519.Verify(key, msg, signature)
    return res, nil
}
