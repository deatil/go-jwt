## Go-jwt

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-jwt" ><img src="https://pkg.go.dev/badge/deatil/go-jwt.svg" alt="Go Reference"></a>
<a href="https://codecov.io/gh/deatil/go-jwt" ><img src="https://codecov.io/gh/deatil/go-jwt/graph/badge.svg?token=SS2Z1IY0XL"/></a>
<a href="https://goreportcard.com/report/github.com/deatil/go-jwt" ><img src="https://goreportcard.com/badge/github.com/deatil/go-jwt" /></a>
</p>


### Desc

*  A JWT (JSON Web Token) library for go.


### What the heck is a JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about reserved keys and the proper way to add your own.


### What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are HMAC SHA, RSA, RSA-PSS, and ECDSA, though hooks are present for adding your own.


### Download

~~~go
go get -u github.com/deatil/go-jwt
~~~


### Get Starting

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-jwt/jwt"
)

func main() {
    claims := map[string]string{
        "aud": "example.com",
        "sub": "foo",
    }
    key := []byte("test-key")

    s := jwt.SigningMethodHMD5.New()
    tokenString, err := s.Sign(claims, key)
    if err != nil {
        fmt.Printf("Sign: %s \n", err.Error())
        return
    }

    fmt.Printf("Signed: %s \n", tokenString)

    p := jwt.SigningMethodHMD5.New()
    parsed, err := p.Parse(tokenString, key)
    if err != nil {
        fmt.Printf("Parse: %s \n", err.Error())
        return
    }

    claims2, err := parsed.GetClaims()
    if err != nil {
        fmt.Printf("GetClaims: %s \n", err.Error())
        return
    }

    aud := claims2["aud"].(string)
    fmt.Printf("Parseed aud: %s \n", aud)
}
~~~


### Token Validator

~~~go
package main

import (
    "fmt"
    "time"

    "github.com/deatil/go-jwt/jwt"
)

func main() {
    tokenString := "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU"

    token := jwt.NewToken(jwt.NewJoseEncoder())
    token.parse(tokenString)

    validator, err := jwt.NewValidator(token)
    if err != nil {
        fmt.Printf("NewValidator: %s \n", err.Error())
        return
    }

    // validator.withLeeway(3)

    // output:
    // HasBeenIssuedBy: true
    fmt.Printf("HasBeenIssuedBy: %v \n", .{validator.HasBeenIssuedBy("iss")})

    // now := time.Now().Unix()

    // have functions:
    // validator.HasBeenIssuedBy("iss") // iss
    // validator.IsRelatedTo("sub") // sub
    // validator.IsIdentifiedBy("jti rrr") // jti
    // validator.IsPermittedFor("example.com") // audience
    // validator.HasBeenIssuedBefore(now) // iat, now is time timestamp
    // validator.IsMinimumTimeBefore(now) // nbf, now is time timestamp
    // validator.IsExpired(now) // exp, now is time timestamp
}
~~~


### Signing Methods

The JWT library have signing methods:

 - `RS256`: jwt.SigningMethodRS256
 - `RS384`: jwt.SigningMethodRS384
 - `RS512`: jwt.SigningMethodRS512

 - `PS256`: jwt.SigningMethodPS256
 - `PS384`: jwt.SigningMethodPS384
 - `PS512`: jwt.SigningMethodPS512

 - `ES256`: jwt.SigningMethodES256
 - `ES384`: jwt.SigningMethodES384
 - `ES512`: jwt.SigningMethodES512

 - `EdDSA`: jwt.SigningMethodEdDSA
 - `ED25519`: jwt.SigningMethodED25519

 - `HMD5`: jwt.SigningMethodHMD5
 - `HSHA1`: jwt.SigningMethodHSHA1
 - `HS224`: jwt.SigningMethodHS224
 - `HS256`: jwt.SigningMethodHS256
 - `HS384`: jwt.SigningMethodHS384
 - `HS512`: jwt.SigningMethodHS512

 - `BLAKE2B`: jwt.SigningMethodBLAKE2B

 - `none`: jwt.SigningMethodNone


### Custom Signing Method

~~~go
package jwt

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ecdsa"
    "math/big"

    "github.com/deatil/go-jwt/jwt"
)

var (
    SigningES256 = NewSignECDSA(crypto.SHA256, 32, "ES256")

    // use the struct
    SigningMethodES256 = jwt.NewJWT[*ecdsa.PrivateKey, *ecdsa.PublicKey](SigningES256, jwt.NewJoseEncoder())
)

type SignECDSA struct {
    Name    string
    Hash    crypto.Hash
    KeySize int
}

func NewSignECDSA(hash crypto.Hash, keySize int, name string) *SignECDSA {
    return &SignECDSA{
        Name:    name,
        Hash:    hash,
        KeySize: keySize,
    }
}

func (s *SignECDSA) Alg() string {
    return s.Name
}

func (s *SignECDSA) SignLength() int {
    return 2*s.KeySize
}

func (s *SignECDSA) Sign(msg []byte, key *ecdsa.PrivateKey) ([]byte, error) {
    hasher := s.Hash.New()
    hasher.Write([]byte(msg))

    rr, ss, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
    if err != nil {
        return nil, err
    }

    keyBytes := s.KeySize

    signed := make([]byte, 2*keyBytes)
    rr.FillBytes(signed[0:keyBytes])
    ss.FillBytes(signed[keyBytes:])

    return signed, nil
}

func (s *SignECDSA) Verify(msg []byte, signature []byte, key *ecdsa.PublicKey) (bool, error) {
    signLength := s.SignLength()
    if len(signature) != signLength {
        return false, errors.New("go-jwt: sign length error")
    }

    rr := big.NewInt(0).SetBytes(signature[:s.KeySize])
    ss := big.NewInt(0).SetBytes(signature[s.KeySize:])

    hasher := s.Hash.New()
    hasher.Write([]byte(msg))

    res := ecdsa.Verify(key, hasher.Sum(nil), rr, ss)
    return res, nil
}
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
