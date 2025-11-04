package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func Test_SigningMethodBLAKE2B_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("12345678901234567890as1234567890")

	s := SigningMethodBLAKE2B.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "BLAKE2B" {
		t.Errorf("Alg got %s, want %s", alg, "BLAKE2B")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHMD5_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHMD5.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHSHA1_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHSHA1.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS224_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS224.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS256_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS256" {
		t.Errorf("Alg got %s, want %s", alg, "HS256")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS384_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS384.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS512_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS512.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodEdDSA_Parse(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodEdDSA.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[ed25519.PublicKey](tokenString, func(t *Token) (ed25519.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodED25519_Parse(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodED25519.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[ed25519.PublicKey](tokenString, func(t *Token) (ed25519.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodES256_Parse(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	s := SigningMethodES256.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*ecdsa.PublicKey](tokenString, func(t *Token) (*ecdsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodES384_Parse(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	s := SigningMethodES384.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*ecdsa.PublicKey](tokenString, func(t *Token) (*ecdsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodES512_Parse(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	s := SigningMethodES512.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*ecdsa.PublicKey](tokenString, func(t *Token) (*ecdsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodRS256_Parse(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseRSAPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodRS256.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*rsa.PublicKey](tokenString, func(t *Token) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodRS384_Parse(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseRSAPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodRS384.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*rsa.PublicKey](tokenString, func(t *Token) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodRS512_Parse(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseRSAPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodRS512.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*rsa.PublicKey](tokenString, func(t *Token) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodPS256_Parse(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseRSAPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodPS256.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*rsa.PublicKey](tokenString, func(t *Token) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodPS384_Parse(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseRSAPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodPS384.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*rsa.PublicKey](tokenString, func(t *Token) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodPS512_Parse(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseRSAPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	s := SigningMethodPS512.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*rsa.PublicKey](tokenString, func(t *Token) (*rsa.PublicKey, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodNone_Parse(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("")

	s := SigningMethodNone.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "none" {
		t.Errorf("Alg got %s, want %s", alg, "none")
	}
	if signLength != 0 {
		t.Errorf("SignLength got %d, want %d", signLength, 0)
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS256_Parse_With_Encoder(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS256" {
		t.Errorf("Alg got %s, want %s", alg, "HS256")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	}, JWTParserOption)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_GetSigningMethodAlgs(t *testing.T) {
	algs := GetSigningMethodAlgs()
	if len(algs) <= 0 {
		t.Error("GetSigningMethodAlgs should not empty")
	}

}

func Test_JWTParse_Error(t *testing.T) {
	var check1 = "eyJ0eXAiO123V0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	_, err = SigningMethodES256.Parse(check1, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}
	checkerr := "invalid character ';' after object key"
	if err.Error() != checkerr {
		t.Errorf("Parse got %s, want %s", err.Error(), checkerr)
	}
}

var (
	SigningTestEdDSD = NewTestSignEdDSD("EdDSD")
)

type testSignEdDSD struct {
	Name string
}

func NewTestSignEdDSD(name string) *testSignEdDSD {
	return &testSignEdDSD{
		Name: name,
	}
}

// Signer algo name.
func (s *testSignEdDSD) Alg() string {
	return s.Name
}

// Signer signed bytes length.
func (s *testSignEdDSD) SignLength() int {
	return 100
}

func Test_Parse_Error(t *testing.T) {
	{
		var check1 = "eyJ0eXAiO123V0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		publicKey := &privateKey.PublicKey

		_, err = Parse[*ecdsa.PublicKey](check1, func(t *Token) (*ecdsa.PublicKey, error) {
			return publicKey, nil
		})
		if err == nil {
			t.Error("Parse should return error")
		}
		checkerr := "invalid character ';' after object key"
		if err.Error() != checkerr {
			t.Errorf("Parse got %s, want %s", err.Error(), checkerr)
		}

	}

	{
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		s := SigningMethodEdDSA.New()

		claims := map[string]string{
			"aud": "example.com",
			"sub": "foo",
		}
		header := map[string]string{
			"alg": "EdDSA",
		}

		tokenString, err := s.SignWithHeader(header, claims, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		parsed, err := Parse[ed25519.PublicKey](tokenString, func(t *Token) (ed25519.PublicKey, error) {
			return publicKey, nil
		})
		if err != nil {
			t.Fatal(err)
		}

		claims2, err := parsed.GetClaims()
		if err != nil {
			t.Fatal(err)
		}

		if claims2["aud"].(string) != claims["aud"] {
			t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
		}
		if claims2["sub"].(string) != claims["sub"] {
			t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
		}

	}

	{
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		s := SigningMethodEdDSA.New()

		claims := map[string]string{
			"aud": "example.com",
			"sub": "foo",
		}
		header := map[string]string{
			"alg": "EdDST",
		}

		tokenString, err := s.SignWithHeader(header, claims, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		_, err = Parse[ed25519.PublicKey](tokenString, func(t *Token) (ed25519.PublicKey, error) {
			return publicKey, nil
		})
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTMethodExists) {
			t.Errorf("Parse error, got %s, want %s", err, ErrJWTMethodInvalid)
		}

	}

	{
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		s := SigningMethodEdDSA.New()

		claims := map[string]string{
			"aud": "example.com",
			"sub": "foo",
		}
		header := map[string]string{
			"alg": "EdDSA",
		}

		tokenString, err := s.SignWithHeader(header, claims, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		newTokenString := tokenString[:len(tokenString)-6] + "00000"

		_, err = Parse[ed25519.PublicKey](newTokenString, func(t *Token) (ed25519.PublicKey, error) {
			return publicKey, nil
		})
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTVerifyFail) {
			t.Errorf("Parse error, got %s, want %s", err, ErrJWTVerifyFail)
		}

	}

	{
		var check1 = "eyJ0eXAiO123V0UiLCJhbGciOiJFUzI1NiJ9"

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		publicKey := &privateKey.PublicKey

		_, err = Parse[*ecdsa.PublicKey](check1, func(t *Token) (*ecdsa.PublicKey, error) {
			return publicKey, nil
		})
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTTokenInvalid) {
			t.Errorf("Parse got %s, want %s", err.Error(), ErrJWTTokenInvalid)
		}

	}

	{
		var check1 = "eyJ0eXAiO123V0UiLCJhbGciOiJFUzI1NiJ9"

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		publicKey := &privateKey.PublicKey

		p := SigningMethodES256.New()
		_, err = p.Parse(check1, publicKey)
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTTokenInvalid) {
			t.Errorf("Parse got %s, want %s", err.Error(), ErrJWTTokenInvalid)
		}

	}

	{
		RegisterSigningMethod(SigningTestEdDSD.Alg(), func() any {
			return SigningTestEdDSD
		})

		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		s := SigningMethodEdDSA.New()

		claims := map[string]string{
			"aud": "example.com",
			"sub": "foo",
		}
		header := map[string]string{
			"alg": "EdDSD",
		}

		tokenString, err := s.SignWithHeader(header, claims, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		_, err = Parse[ed25519.PublicKey](tokenString, func(t *Token) (ed25519.PublicKey, error) {
			return publicKey, nil
		})
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTMethodInvalid) {
			t.Errorf("Parse error, got %s, want %s", err, ErrJWTMethodInvalid)
		}

	}

}

func Test_SigningMethodES256_JWTStrictEncoder(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	s := SigningMethodES256.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodES256.New()
	p.WithEncoder(JWTStrictEncoder)
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS256_Parse_With_Encoder2(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS256" {
		t.Errorf("Alg got %s, want %s", alg, "HS256")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	parsed, err := Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	}, ParserOption{
		Encoder: JWTStrictEncoder,
		ValidMethods: []string{
			"HS256",
			"HS384",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodHS256_Parse_With_Encoder2_Error(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS256" {
		t.Errorf("Alg got %s, want %s", alg, "HS256")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	_, err = Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	}, ParserOption{
		Encoder: JWTEncoder,
		ValidMethods: []string{
			"HS384",
			"HS512",
		},
	})
	if err == nil {
		t.Error("Parse should return error")
	}
	checkerr := "go-jwt: token signature is invalid: signing method HS256 is invalid"
	if err.Error() != checkerr {
		t.Errorf("Parse got %s, want %s", err.Error(), checkerr)
	}

}

func Test_SigningMethodHS256_Parse_With_Encoder2_Error2(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		return key, nil
	}, ParserOption{})
	if err == nil {
		t.Error("Parse should return error")
	}
	checkerr := "go-jwt: Encoder invalid"
	if err.Error() != checkerr {
		t.Errorf("Parse got %s, want %s", err.Error(), checkerr)
	}

}

func Test_SigningMethodHS256_Parse_With_Encoder2_Error3(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS256" {
		t.Errorf("Alg got %s, want %s", alg, "HS256")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	_, err = Parse[[]byte](tokenString, func(t *Token) ([]byte, error) {
		header, err := t.GetHeader()
		if err != nil {
			return nil, err
		}

		if header.Alg != "HS257" {
			return nil, errors.New("should alg HS257")
		}

		return key, nil
	}, ParserOption{
		Encoder: JWTEncoder,
		ValidMethods: []string{
			"HS384",
			"HS512",
		},
	})
	if err == nil {
		t.Error("Parse should return error")
	}
	checkerr := "should alg HS257"
	if err.Error() != checkerr {
		t.Errorf("Parse got %s, want %s", err.Error(), checkerr)
	}

}
