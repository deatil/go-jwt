package jwt

import (
	"bytes"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2b"
)

var (
	SigningBLAKE2B = NewSignBlake2b(blake2b.New256, "BLAKE2B")
)

var (
	ErrVerifyKeyTooShort     = errors.New("go-jwt: SignBlake2b key too short")
	ErrSignBlake2bVerifyFail = errors.New("go-jwt: SignBlake2b Verify fail")
)

type SignBlake2b struct {
	NewHash func([]byte) (hash.Hash, error)
	Name    string
}

func NewSignBlake2b(newHash func([]byte) (hash.Hash, error), name string) *SignBlake2b {
	return &SignBlake2b{
		NewHash: newHash,
		Name:    name,
	}
}

func (s *SignBlake2b) Alg() string {
	return s.Name
}

func (s *SignBlake2b) SignLength() int {
	h, _ := s.NewHash(nil)
	return h.Size()
}

func (s *SignBlake2b) Sign(msg []byte, key []byte) ([]byte, error) {
	if len(key)*8 < 256 {
		return nil, ErrVerifyKeyTooShort
	}

	h, err := s.NewHash(key)
	if err != nil {
		return nil, err
	}

	h.Write(msg)

	data := h.Sum(nil)

	return data, nil
}

func (s *SignBlake2b) Verify(msg []byte, signature []byte, key []byte) (bool, error) {
	if len(key)*8 < 256 {
		return false, ErrVerifyKeyTooShort
	}

	h, err := s.NewHash(key)
	if err != nil {
		return false, err
	}

	h.Write(msg)

	data := h.Sum(nil)
	if bytes.Compare(data, signature) == 0 {
		return true, nil
	}

	return false, ErrSignBlake2bVerifyFail
}
