package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
)

var (
	ErrNotECPublicKey  = errors.New("go-jwt: key is not a valid ECDSA public key")
	ErrNotECPrivateKey = errors.New("go-jwt: key is not a valid ECDSA private key")
)

// ParseECPrivateKeyFromPEM parses a PEM encoded Elliptic Curve Private Key Structure
func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	der, err := ParsePEM(key)
	if err != nil {
		return nil, err
	}

	return ParseECPrivateKeyFromDer(der)
}

// ParseECPublicKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
	der, err := ParsePEM(key)
	if err != nil {
		return nil, err
	}

	return ParseECPublicKeyFromDer(der)
}

func ParseECPrivateKeyFromDer(der []byte) (*ecdsa.PrivateKey, error) {
	var err error

	var parsedKey any
	if parsedKey, err = x509.ParseECPrivateKey(der); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
			return nil, err
		}
	}

	if pkey, ok := parsedKey.(*ecdsa.PrivateKey); ok {
		return pkey, nil
	}

	return nil, ErrNotECPrivateKey
}

func ParseECPublicKeyFromDer(der []byte) (*ecdsa.PublicKey, error) {
	var err error

	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(der); err != nil {
		if cert, err := x509.ParseCertificate(der); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	if pkey, ok := parsedKey.(*ecdsa.PublicKey); ok {
		return pkey, nil
	}

	return nil, ErrNotECPublicKey
}
