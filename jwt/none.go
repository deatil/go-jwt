package jwt

import (
	"errors"
)

var (
	SigningNone = NewSignNone("none")
)

var ErrSignNoneSignatureInvalid = errors.New("go-jwt: SignNone verify signature not empty")

type SignNone struct {
	Name string
}

func NewSignNone(name string) *SignNone {
	return &SignNone{
		Name: name,
	}
}

func (s *SignNone) Alg() string {
	return s.Name
}

func (s *SignNone) SignLength() int {
	return 0
}

func (s *SignNone) Sign(msg []byte, key []byte) ([]byte, error) {
	return nil, nil
}

func (s *SignNone) Verify(msg []byte, signature []byte, key []byte) (bool, error) {
	if len(signature) > 0 {
		return false, ErrSignNoneSignatureInvalid
	}

	return true, nil
}
