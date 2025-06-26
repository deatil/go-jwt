package jwt

import (
    "errors"
    "crypto/rsa"
    "crypto/x509"
)

var (
    ErrNotRSAPrivateKey = errors.New("go-jwt: key is not a valid RSA private key")
    ErrNotRSAPublicKey  = errors.New("go-jwt: key is not a valid RSA public key")
)

// ParseRSAPrivateKeyFromDer parses a PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromDer(der []byte) (*rsa.PrivateKey, error) {
    var err error

    var parsedKey any
    if parsedKey, err = x509.ParsePKCS1PrivateKey(der); err != nil {
        if parsedKey, err = x509.ParsePKCS8PrivateKey(der); err != nil {
            return nil, err
        }
    }

    var pkey *rsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
        return nil, ErrNotRSAPrivateKey
    }

    return pkey, nil
}

// ParseRSAPublicKeyFromDer parses a PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromDer(der []byte) (*rsa.PublicKey, error) {
    var err error

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParsePKCS1PublicKey(der); err != nil {
        if parsedKey, err = x509.ParsePKIXPublicKey(der); err != nil {
            if cert, err := x509.ParseCertificate(der); err == nil {
                parsedKey = cert.PublicKey
            } else {
                return nil, err
            }
        }
    }

    if pkey, ok := parsedKey.(*rsa.PublicKey); ok {
        return pkey, nil
    }

    return nil, ErrNotRSAPublicKey
}
