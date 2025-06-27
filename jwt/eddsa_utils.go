package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
)

var (
	ErrNotEdPrivateKey = errors.New("go-jwt: key is not a valid Ed25519 private key")
	ErrNotEdPublicKey  = errors.New("go-jwt: key is not a valid Ed25519 public key")
)

// ParseEdPrivateKeyFromDer parses a PEM-encoded Edwards curve private key
func ParseEdPrivateKeyFromDer(der []byte) (ed25519.PrivateKey, error) {
	var err error

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		return nil, err
	}

	if pkey, ok := parsedKey.(ed25519.PrivateKey); ok {
		return pkey, nil
	}

	return nil, ErrNotEdPrivateKey
}

// ParseEdPublicKeyFromDer parses a PEM-encoded Edwards curve public key
func ParseEdPublicKeyFromDer(der []byte) (ed25519.PublicKey, error) {
	var err error

	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(der); err != nil {
		return nil, err
	}

	if pkey, ok := parsedKey.(ed25519.PublicKey); ok {
		return pkey, nil
	}

	return nil, ErrNotEdPublicKey
}
