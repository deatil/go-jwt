package jwt

import (
	"crypto/mldsa"
	"crypto/x509"
	"errors"
)

var (
	ErrNotMLDSAPublicKey  = errors.New("go-jwt: key is not a valid MLDSA public key")
	ErrNotMLDSAPrivateKey = errors.New("go-jwt: key is not a valid MLDSA private key")
)

// ParseMLDSAPrivateKeyFromPEM parses a PEM encoded Private Key Structure
func ParseMLDSAPrivateKeyFromPEM(key []byte) (*mldsa.PrivateKey, error) {
	der, err := ParsePEM(key)
	if err != nil {
		return nil, err
	}

	return ParseMLDSAPrivateKeyFromDer(der)
}

// ParseMLDSAPublicKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 public key
func ParseMLDSAPublicKeyFromPEM(key []byte) (*mldsa.PublicKey, error) {
	der, err := ParsePEM(key)
	if err != nil {
		return nil, err
	}

	return ParseMLDSAPublicKeyFromDer(der)
}

func ParseMLDSAPrivateKeyFromDer(der []byte) (*mldsa.PrivateKey, error) {
	var err error
	var parsedKey any
	if parsedKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		return nil, err
	}

	if pkey, ok := parsedKey.(*mldsa.PrivateKey); ok {
		return pkey, nil
	}

	return nil, ErrNotMLDSAPrivateKey
}

func ParseMLDSAPublicKeyFromDer(der []byte) (*mldsa.PublicKey, error) {
	var err error

	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(der); err != nil {
		if cert, err := x509.ParseCertificate(der); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	if pkey, ok := parsedKey.(*mldsa.PublicKey); ok {
		return pkey, nil
	}

	return nil, ErrNotMLDSAPublicKey
}
