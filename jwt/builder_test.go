package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func Test_SigningMethodES256_Builder(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	now := time.Now()
	exp := now.AddDate(0, 1, 5)
	nbf := now.AddDate(0, 0, 1)

	s := SigningMethodES256.New()

	b := s.Build()
	b.WithHeader(RegisteredHeadersType, "JWT")
	b.WithHeader(RegisteredHeadersAlgorithm, s.Alg())
	b.PermittedFor(NewClaimSingleString("audience"))
	b.ExpiresAt(NewNumericDate(exp))
	b.IdentifiedBy("JwtId")
	b.IssuedAt(NewNumericDate(now))
	b.IssuedBy("issuer")
	b.CanOnlyBeUsedAfter(NewNumericDate(nbf))
	b.RelatedTo("subject")

	token, err := b.GetToken(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := token.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodES256.New()
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != "audience" {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), "audience")
	}
	if claims2["sub"].(string) != "subject" {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), "subject")
	}
	if claims2["jti"].(string) != "JwtId" {
		t.Errorf("GetClaims jti got %s, want %s", claims2["jti"].(string), "JwtId")
	}
	if claims2["iss"].(string) != "issuer" {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), "issuer")
	}

	if claims2["iat"].(float64) != float64(now.Unix()) {
		t.Errorf("GetClaims iat got %f, want %d", claims2["iat"].(float64), now.Unix())
	}
	if claims2["exp"].(float64) != float64(exp.Unix()) {
		t.Errorf("GetClaims exp got %f, want %d", claims2["exp"].(float64), exp.Unix())
	}
	if claims2["nbf"].(float64) != float64(nbf.Unix()) {
		t.Errorf("GetClaims nbf got %f, want %d", claims2["nbf"].(float64), nbf.Unix())
	}
}

func Test_SigningMethodES256_Builder2(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	now := time.Now()
	exp := now.AddDate(0, 1, 5)
	nbf := now.AddDate(0, 0, 1)

	s := SigningMethodES256.New()

	b := s.Build()
	b.HeaderType("JWT")
	b.HeaderAlgo(s.Alg())
	b.WithHeader("ui", "JWK")
	b.PermittedFor(NewClaimSingleString("audience"))
	b.ExpiresAt(NewNumericDate(exp))
	b.IdentifiedBy("JwtId")
	b.IssuedAt(NewNumericDate(now))
	b.IssuedBy("issuer")
	b.CanOnlyBeUsedAfter(NewNumericDate(nbf))
	b.RelatedTo("subject")
	b.WithClaim("userid", "test")

	token, err := b.GetToken(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := token.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodES256.New()
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2, err := parsed.GetHeaders()
	if err != nil {
		t.Fatal(err)
	}

	if header2["typ"] != "JWT" {
		t.Errorf("GetHeaders typ got %s, want %s", header2["typ"], "JWT")
	}
	if header2["alg"] != "ES256" {
		t.Errorf("GetHeaders alg got %s, want %s", header2["alg"], "ES256")
	}
	if header2["ui"] != "JWK" {
		t.Errorf("GetHeaders ui got %s, want %s", header2["ui"], "JWK")
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != "audience" {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), "audience")
	}
	if claims2["sub"].(string) != "subject" {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), "subject")
	}
	if claims2["jti"].(string) != "JwtId" {
		t.Errorf("GetClaims jti got %s, want %s", claims2["jti"].(string), "JwtId")
	}
	if claims2["iss"].(string) != "issuer" {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), "issuer")
	}
	if claims2["userid"].(string) != "test" {
		t.Errorf("GetClaims userid got %s, want %s", claims2["userid"].(string), "test")
	}

	if claims2["iat"].(float64) != float64(now.Unix()) {
		t.Errorf("GetClaims iat got %f, want %d", claims2["iat"].(float64), now.Unix())
	}
	if claims2["exp"].(float64) != float64(exp.Unix()) {
		t.Errorf("GetClaims exp got %f, want %d", claims2["exp"].(float64), exp.Unix())
	}
	if claims2["nbf"].(float64) != float64(nbf.Unix()) {
		t.Errorf("GetClaims nbf got %f, want %d", claims2["nbf"].(float64), nbf.Unix())
	}
}

func Test_SigningMethodES256_Builder3(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	now := time.Now()
	exp := now.AddDate(0, 1, 5)
	nbf := now.AddDate(0, 0, 1)

	s := SigningMethodES256.New()

	b := s.Build()
	b.WithHeader("ui", "JWK")
	b.PermittedFor(NewClaimSingleString("audience"))
	b.ExpiresAt(NewNumericDate(exp))
	b.IdentifiedBy("JwtId")
	b.IssuedAt(NewNumericDate(now))
	b.IssuedBy("issuer")
	b.CanOnlyBeUsedAfter(NewNumericDate(nbf))
	b.RelatedTo("subject")
	b.WithClaim("userid", "test")

	token, err := b.GetToken(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	tokenString, err := token.SignedString()
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodES256.New()
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2, err := parsed.GetHeaders()
	if err != nil {
		t.Fatal(err)
	}

	if header2["typ"] != "JWT" {
		t.Errorf("GetHeaders typ got %s, want %s", header2["typ"], "JWT")
	}
	if header2["alg"] != "ES256" {
		t.Errorf("GetHeaders alg got %s, want %s", header2["alg"], "ES256")
	}
	if header2["ui"] != "JWK" {
		t.Errorf("GetHeaders ui got %s, want %s", header2["ui"], "JWK")
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != "audience" {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), "audience")
	}
	if claims2["sub"].(string) != "subject" {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), "subject")
	}
	if claims2["jti"].(string) != "JwtId" {
		t.Errorf("GetClaims jti got %s, want %s", claims2["jti"].(string), "JwtId")
	}
	if claims2["iss"].(string) != "issuer" {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), "issuer")
	}
	if claims2["userid"].(string) != "test" {
		t.Errorf("GetClaims userid got %s, want %s", claims2["userid"].(string), "test")
	}

	if claims2["iat"].(float64) != float64(now.Unix()) {
		t.Errorf("GetClaims iat got %f, want %d", claims2["iat"].(float64), now.Unix())
	}
	if claims2["exp"].(float64) != float64(exp.Unix()) {
		t.Errorf("GetClaims exp got %f, want %d", claims2["exp"].(float64), exp.Unix())
	}
	if claims2["nbf"].(float64) != float64(nbf.Unix()) {
		t.Errorf("GetClaims nbf got %f, want %d", claims2["nbf"].(float64), nbf.Unix())
	}
}
