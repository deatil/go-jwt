package jwt

import (
    "hash"
    "bytes"
    "errors"
    "crypto/md5"
    "crypto/sha1"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
)

var (
    SigningHMD5  = NewSignHmac(md5.New, "HMD5")
    SigningHSHA1 = NewSignHmac(sha1.New, "HSHA1")
    SigningHS224 = NewSignHmac(sha256.New224, "HS224")
    SigningHS256 = NewSignHmac(sha256.New, "HS256")
    SigningHS384 = NewSignHmac(sha512.New384, "HS384")
    SigningHS512 = NewSignHmac(sha512.New, "HS512")
)

type SignHmac struct {
    Hash func() hash.Hash
    Name string
}

func NewSignHmac(hash func() hash.Hash, name string) *SignHmac {
    return &SignHmac{
        Hash: hash,
        Name: name,
    }
}

func (s *SignHmac) Alg() string {
    return s.Name
}

func (s *SignHmac) SignLength() int {
    return s.Hash().Size()
}

func (s *SignHmac) Sign(msg []byte, key []byte) ([]byte, error) {
    mac := hmac.New(s.Hash, key)
    mac.Write(msg)

    data := mac.Sum(nil)

    return data, nil
}

func (s *SignHmac) Verify(msg []byte, signature []byte, key []byte) (bool, error) {
    mac := hmac.New(s.Hash, key)
    mac.Write(msg)

    data := mac.Sum(nil)
    if bytes.Compare(data, signature) == 0 {
        return true, nil
    }

    return false, errors.New("go-jwt: SignHmac Verify false")
}
