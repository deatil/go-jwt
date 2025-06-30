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

func Test_SigningMethodHMD5(t *testing.T) {
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

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HMD5" {
		t.Errorf("Alg got %s, want %s", alg, "HMD5")
	}
	if signLength != 16 {
		t.Errorf("SignLength got %d, want %d", signLength, 16)
	}

	p := SigningMethodHMD5.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodHSHA1(t *testing.T) {
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

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HSHA1" {
		t.Errorf("Alg got %s, want %s", alg, "HSHA1")
	}
	if signLength != 20 {
		t.Errorf("SignLength got %d, want %d", signLength, 20)
	}

	p := SigningMethodHSHA1.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodHS224(t *testing.T) {
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

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS224" {
		t.Errorf("Alg got %s, want %s", alg, "HS224")
	}
	if signLength != 28 {
		t.Errorf("SignLength got %d, want %d", signLength, 28)
	}

	p := SigningMethodHS224.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodHS256(t *testing.T) {
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

	p := SigningMethodHS256.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodHS384(t *testing.T) {
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

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS384" {
		t.Errorf("Alg got %s, want %s", alg, "HS384")
	}
	if signLength != 48 {
		t.Errorf("SignLength got %d, want %d", signLength, 48)
	}

	p := SigningMethodHS384.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodHS512(t *testing.T) {
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

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS512" {
		t.Errorf("Alg got %s, want %s", alg, "HS512")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	p := SigningMethodHS512.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodNone(t *testing.T) {
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

	p := SigningMethodNone.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodHS256_Check(t *testing.T) {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	tokenStr := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	claims := map[string]any{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	}
	keyBytes := fromHex(key)

	s := SigningMethodHS256.New()
	tokenString, err := s.Sign(claims, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	p := SigningMethodHS256.New()
	parsed, err := p.Parse(tokenStr, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["iss"].(string) != claims["iss"] {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), claims["iss"])
	}

}

func Test_SigningMethodHS384_Check(t *testing.T) {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	tokenStr := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy"

	claims := map[string]any{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	}
	keyBytes := fromHex(key)

	s := SigningMethodHS384.New()
	tokenString, err := s.Sign(claims, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	p := SigningMethodHS384.New()
	parsed, err := p.Parse(tokenStr, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["iss"].(string) != claims["iss"] {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), claims["iss"])
	}

}

func Test_SigningMethodHS512_Check(t *testing.T) {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	tokenStr := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw"

	claims := map[string]any{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	}
	keyBytes := fromHex(key)

	s := SigningMethodHS512.New()
	tokenString, err := s.Sign(claims, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	p := SigningMethodHS512.New()
	parsed, err := p.Parse(tokenStr, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["iss"].(string) != claims["iss"] {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), claims["iss"])
	}

}

func Test_SigningMethodHS256_Check_fail(t *testing.T) {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	tokenStr := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo"

	keyBytes := fromHex(key)

	p := SigningMethodHS256.New()
	_, err := p.Parse(tokenStr, keyBytes)
	if err == nil {
		t.Error("Parse should return error")
	}

}

func Test_GetTokenHeader(t *testing.T) {
	tokenStr := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	header, err := GetTokenHeader(tokenStr)
	if err != nil {
		t.Fatal(err)
	}

	if header.Alg != "ES256" {
		t.Errorf("GetTokenHeader Alg got %s, want %s", header.Alg, "ES256")
	}

}

func Test_SigningMethodBLAKE2B(t *testing.T) {
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

	p := SigningMethodBLAKE2B.New()
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodBLAKE2B_Check(t *testing.T) {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	tokenStr := "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb9M"

	claims := map[string]any{
		"iss":                        "joe",
		"exp":                        1300819380,
		"http://example.com/is_root": true,
	}
	keyBytes := fromHex(key)

	s := SigningMethodBLAKE2B.New()
	tokenString, err := s.Sign(claims, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	p := SigningMethodBLAKE2B.New()
	parsed, err := p.Parse(tokenStr, keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["iss"].(string) != claims["iss"] {
		t.Errorf("GetClaims iss got %s, want %s", claims2["iss"].(string), claims["iss"])
	}

}

func Test_SigningMethodBLAKE2B_Check_fail(t *testing.T) {
	key := "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3"
	tokenStr := "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb12"

	keyBytes := fromHex(key)

	p := SigningMethodBLAKE2B.New()
	_, err := p.Parse(tokenStr, keyBytes)
	if err == nil {
		t.Error("Parse should return error")
	}

}

func Test_parse_JWTTypeInvalid(t *testing.T) {
	var tokenString = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodEdDSA.New()
	_, err = p.Parse(tokenString, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

	check := "go-jwt: Type invalid"
	if err.Error() != check {
		t.Errorf("Parse err got %s, want %s", err.Error(), check)
	}

}

func Test_parse_JWTSignatureInvalid(t *testing.T) {
	var tokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	p := SigningMethodES256.New()
	_, err = p.Parse(tokenString, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

	check := "go-jwt: Verify fail"
	if err.Error() != check {
		t.Errorf("Parse err got %s, want %s", err.Error(), check)
	}

}

func Test_SigningMethodEdDSA_signWithHeader(t *testing.T) {
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
		"typ": "JWT",
		"alg": s.Alg(),
		"tuy": "data123",
	}

	tokenString, err := s.SignWithHeader(header, claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "EdDSA" {
		t.Errorf("Alg got %s, want %s", alg, "EdDSA")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	p := SigningMethodEdDSA.New()
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2, err := parsed.GetHeaders()
	if err != nil {
		t.Fatal(err)
	}

	if header2["typ"].(string) != header["typ"] {
		t.Errorf("GetClaims typ got %s, want %s", header2["typ"].(string), header["typ"])
	}
	if header2["alg"].(string) != header["alg"] {
		t.Errorf("GetClaims alg got %s, want %s", header2["alg"].(string), header["alg"])
	}
	if header2["tuy"].(string) != header["tuy"] {
		t.Errorf("GetClaims tuy got %s, want %s", header2["tuy"].(string), header["tuy"])
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodEdDSA(t *testing.T) {
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

	p := SigningMethodEdDSA.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodES256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	s := SigningMethodES256.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
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

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodES384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

	p := SigningMethodES384.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodES512(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
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

	p := SigningMethodES512.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodRS256(t *testing.T) {
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

	p := SigningMethodRS256.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodRS384(t *testing.T) {
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

	p := SigningMethodRS384.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodRS512(t *testing.T) {
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

	p := SigningMethodRS512.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodPS256(t *testing.T) {
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

	p := SigningMethodPS256.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodPS384(t *testing.T) {
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

	p := SigningMethodPS384.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodPS512(t *testing.T) {
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

	p := SigningMethodPS512.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodEdDSA_Check(t *testing.T) {
	var pub_key = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1"
	var pri_key = "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a"
	var tokenStr = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw"

	publicKey := ed25519.PublicKey(fromHex(pub_key))
	privateKey := ed25519.NewKeyFromSeed(fromHex(pri_key))

	s := SigningMethodED25519.New()

	claims := map[string]string{
		"foo": "bar",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodED25519.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodEdDSA_Check_fail(t *testing.T) {
	var pub_key = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1"
	var tokenStr = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXoifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw"

	publicKey := ed25519.PublicKey(fromHex(pub_key))

	p := SigningMethodED25519.New()
	_, err := p.Parse(tokenStr, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

}

func Test_SigningMethodES256_Check(t *testing.T) {
	var prikey = "MHcCAQEEIGA+eFf76fueD/Q12q2KseDD3JvhykSEMzWrGEqEUB0PoAoGCCqGSM49AwEHoUQDQgAEx/h8LwJ5k6RAEN609+I+Wwhq/hnf8ymMrwcsrgSP5jLFnBlCi15LSh3EvJ5FVMvgCE8Hc7GsFNQSY8rtxy6SwA=="
	var pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg=="
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES256.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodES384_Check(t *testing.T) {
	var prikey = "MIGkAgEBBDDYa7rJaU7feLMqrAx6adZFNQOpaUH/UylbZLriOLON5YFVwtVUpO1FfEXZUIQpptSgBwYFK4EEACKhZANiAAR9AjV7L1e4Svk1GrTugK097V2+3U0a0Nw/Ek6t0UVWWad6hffgX5Zw4ovH63ejzsTabmzSNRR+PbvokSs9wJLxJztYI54+LhL4bAAGQ63yISSDXTrKPY1JrFAyIeUz8Js="
	var pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2Gu6yWlO33izKqwMemnWRTUDqWlB/1MpW2S64jizjeWBVcLVVKTtRXxF2VCEKabUT7XOYsSD2OufMoQUm+oq3yCVEj/WmE35SRipP5g5CuLfJlgc4Yg+Qeo4PXBBoRoA"
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.ngAfKMbJUh0WWubSIYe5GMsA-aHNKwFbJk_wq3lq23aPp8H2anb1rRILIzVR0gUf4a8WzDtrzmiikuPWyCS6CN4-PwdgTk-5nehC7JXqlaBZU05p3toM3nWCwm_LXcld"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES384.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES384.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodES512_Check(t *testing.T) {
	var prikey = "MIHcAgEBBEIB0pE4uFaWRx7t03BsYlYvF1YvKaBGyvoakxnodm9ou0R9wC+sJAjHQZZJikOg4SwNqgQ/hyrOuDK2oAVHhgVGcYmgBwYFK4EEACOhgYkDgYYABAAJXIuw12MUzpHggia9POBFYXSxaOGKGbMjIyDI+6q7wi7LMw3HgbaOmgIqFG72o8JBQwYN4IbXHf+f86CRY1AA2wHzbHvt6IhkCXTNxBEffa1yMUgu8n9cKKF2iLgyQKcKqW338fGOw/n3Rm2Yd/EB56u2rnD29qS+nOM9eGS+gy39OQ=="
	var pubkey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQACVyLsNdjFM6R4IImvTzgRWF0sWjhihmzIyMgyPuqu8IuyzMNx4G2jpoCKhRu9qPCQUMGDeCG1x3/n/OgkWNQANsB82x77eiIZAl0zcQRH32tcjFILvJ/XCihdoi4MkCnCqlt9/HxjsP590ZtmHfxAeertq5w9vakvpzjPXhkvoMt/Tk="
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AAU0TvGQOcdg2OvrwY73NHKgfk26UDekh9Prz-L_iWuTBIBqOFCWwwLsRiHB1JOddfKAls5do1W0jR_F30JpVd-6AJeTjGKA4C1A1H6gIKwRY0o_tFDIydZCl_lMBMeG5VNFAjO86-WCSKwc3hqaGkq1MugPRq_qrF9AVbuEB4JPLyL5"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES512.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES512.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodES256_Check_fail(t *testing.T) {
	var pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg=="
	var tokenStr = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.MEQCIHoSJnmGlPaVQDqacx_2XlXEhhqtWceVopjomc2PJLtdAiAUTeGPoNYxZw0z8mgOnnIcjoxRuNDVZvybRZF3wR1l8W"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodES256.New()
	_, err = p.Parse(tokenStr, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

}

func Test_SigningMethodRS256_Check(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodRS256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodRS384_Check(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.W-jEzRfBigtCWsinvVVuldiuilzVdU5ty0MvpLaSaqK9PlAWWlDQ1VIQ_qSKzwL5IXaZkvZFJXT3yL3n7OUVu7zCNJzdwznbC8Z-b0z2lYvcklJYi2VOFRcGbJtXUqgjk2oGsiqUMUMOLP70TTefkpsgqDxbRh9CDUfpOJgW-dU7cmgaoswe3wjUAUi6B6G2YEaiuXC0XScQYSYVKIzgKXJV8Zw-7AN_DBUI4GkTpsvQ9fVVjZM9csQiEXhYekyrKu1nu_POpQonGd8yqkIyXPECNmmqH5jH4sFiF67XhD7_JpkvLziBpI-uh86evBUadmHhb9Otqw3uV3NTaXLzJw"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodRS384.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodRS512_Check(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodRS512.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodRS256_Check_fail(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodRS256.New()
	_, err = p.Parse(tokenStr, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

}

func Test_SigningMethodPS256_Check(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodPS256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodPS384_Check(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.w7-qqgj97gK4fJsq_DCqdYQiylJjzWONvD0qWWWhqEOFk2P1eDULPnqHRnjgTXoO4HAw4YIWCsZPet7nR3Xxq4ZhMqvKW8b7KlfRTb9cH8zqFvzMmybQ4jv2hKc3bXYqVow3AoR7hN_CWXI3Dv6Kd2X5xhtxRHI6IL39oTVDUQ74LACe-9t4c3QRPuj6Pq1H4FAT2E2kW_0KOc6EQhCLWEhm2Z2__OZskDC8AiPpP8Kv4k2vB7l0IKQu8Pr4RcNBlqJdq8dA5D3hk5TLxP8V5nG1Ib80MOMMqoS3FQvSLyolFX-R_jZ3-zfq6Ebsqr0yEb0AH2CfsECF7935Pa0FKQ"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodPS384.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodPS512_Check(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.GX1HWGzFaJevuSLavqqFYaW8_TpvcjQ8KfC5fXiSDzSiT9UD9nB_ikSmDNyDILNdtjZLSvVKfXxZJqCfefxAtiozEDDdJthZ-F0uO4SPFHlGiXszvKeodh7BuTWRI2wL9-ZO4mFa8nq3GMeQAfo9cx11i7nfN8n2YNQ9SHGovG7_T_AvaMZB_jT6jkDHpwGR9mz7x1sycckEo6teLdHRnH_ZdlHlxqknmyTu8Odr5Xh0sJFOL8BepWbbvIIn-P161rRHHiDWFv6nhlHwZnVzjx7HQrWSGb6-s2cdLie9QL_8XaMcUpjLkfOMKkDOfHo6AvpL7Jbwi83Z2ZTHjJWB-A"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodPS512.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodPS256_Check_fail(t *testing.T) {
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9W"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodPS256.New()
	_, err = p.Parse(tokenStr, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

}

func Test_SigningMethodEdDSA_type(t *testing.T) {
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

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "EdDSA" {
		t.Errorf("Alg got %s, want %s", alg, "EdDSA")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	p := SigningMethodEdDSA.New()
	parsed, err := p.Parse(tokenString, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2, err := parsed.GetHeader()
	if err != nil {
		t.Fatal(err)
	}

	if header2.Typ != "" {
		t.Errorf("GetClaims typ got %s", header2.Typ)
	}
	if header2.Alg != header["alg"] {
		t.Errorf("GetClaims alg got %s, want %s", header2.Alg, header["alg"])
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["sub"].(string) != claims["sub"] {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodEdDSA_JWTTypeInvalid(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	header := map[string]string{
		"typ": "JWE",
		"alg": "EdDSA",
	}

	s := SigningMethodEdDSA.New()
	tokenString, err := s.SignWithHeader(header, claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	p := SigningMethodEdDSA.New()
	_, err = p.Parse(tokenString, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

	check := "go-jwt: Type invalid"
	if err.Error() != check {
		t.Errorf("Parse err got %s, want %s", err.Error(), check)
	}

}

func Test_SigningMethodEdDSA_JWTAlgoInvalid(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	header := map[string]string{
		"typ": "JWT",
		"alg": "ED25519",
	}

	s := SigningMethodEdDSA.New()
	tokenString, err := s.SignWithHeader(header, claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	p := SigningMethodEdDSA.New()
	_, err = p.Parse(tokenString, publicKey)
	if err == nil {
		t.Error("Parse should return error")
	}

	check := "go-jwt: Algo invalid"
	if err.Error() != check {
		t.Errorf("Parse err got %s, want %s", err.Error(), check)
	}

}

func Test_SigningMethodES256_with_RegisteredClaims(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	s := SigningMethodES256.New()

	claims := RegisteredClaims{
		Audience: ClaimStrings{
			Value: []string{
				"example.com",
			},
			AsString: true,
		},
		Subject: "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
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

	checkaud := "example.com"
	if claims2["aud"].(string) != checkaud {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), checkaud)
	}
	if claims2["sub"].(string) != claims.Subject {
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims.Subject)
	}

}

func Test_SigningMethodES256_Check_With_PEM_Key(t *testing.T) {
	var prikey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HK
RIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END PUBLIC KEY-----
    `
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	prikeyBytes, _ := ParsePEM([]byte(prikey))
	pubkeyBytes, _ := ParsePEM([]byte(pubkey))

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES256.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodRS256_with_pkcs8_key(t *testing.T) {
	var prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo="
	var pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

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

	p := SigningMethodRS256.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodPS256_with_pkcs8_key(t *testing.T) {
	var prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo="
	var pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

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

	p := SigningMethodPS256.New()
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodRS256_Check_with_pkcs8_key(t *testing.T) {
	var pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodRS256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodPS256_Check_with_pkcs8_key(t *testing.T) {
	var pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w"

	var pubkeyBytes = fromBase64(pubkey)

	publicKey, err := ParseRSAPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodPS256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	check := "bar"
	if claims2["foo"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodES256_Check_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg/DkEwUlK8nWyB30J
RyxjU42bu//wSrGj2szLE/ybKMqgCgYIKoZIzj0DAQehRANCAAROkh8yLuhNymC1
t5DSS6XNiUAotBK3Wl84ZQe0e9x7wwSyy547EIdYkqqX+wn4mslJ+o67kBaUOoaq
nvtkDskL
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpIfMi7oTcpgtbeQ0kulzYlAKLQS
t1pfOGUHtHvce8MEssueOxCHWJKql/sJ+JrJSfqOu5AWlDqGqp77ZA7JCw==
-----END PUBLIC KEY-----
    `
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.WDolEPRIhE9t5azDM_iepn9ezk0dIuExOKFYFAdVS1QC3iOyWM__4ZEAiLgCkGuaPo0ftVQCsCYItjKgVZHgGQ"

	prikeyBytes, _ := ParsePEM([]byte(prikey))
	pubkeyBytes, _ := ParsePEM([]byte(pubkey))

	privateKey, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromDer(pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodES256.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodES256.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	claims2, err := parsed.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodHS224_WithEncoder(t *testing.T) {
	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}
	key := []byte("test-key")

	s := SigningMethodHS224.New()
	s.WithEncoder(JWTEncoder)
	tokenString, err := s.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Error("Sign got fail")
	}

	alg := s.Alg()
	signLength := s.SignLength()

	if alg != "HS224" {
		t.Errorf("Alg got %s, want %s", alg, "HS224")
	}
	if signLength != 28 {
		t.Errorf("SignLength got %d, want %d", signLength, 28)
	}

	p := SigningMethodHS224.New()
	p.WithEncoder(JWTEncoder)
	parsed, err := p.Parse(tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_GetTokenHeader_WithEncoder(t *testing.T) {
	tokenStr := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	header, err := GetTokenHeader(tokenStr, JWTEncoder)
	if err != nil {
		t.Fatal(err)
	}

	if header.Alg != "ES256" {
		t.Errorf("GetTokenHeader Alg got %s, want %s", header.Alg, "ES256")
	}

}

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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[ed25519.PrivateKey, ed25519.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[ed25519.PrivateKey, ed25519.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
	}

}

func Test_SigningMethodES256_Parse(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	s := SigningMethodES256.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse[*ecdsa.PrivateKey, *ecdsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*ecdsa.PrivateKey, *ecdsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*ecdsa.PrivateKey, *ecdsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

	parsed, err := Parse[[]byte, []byte](tokenString, key, JWTEncoder)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

func Test_Parse_Error(t *testing.T) {
	{
		var check1 = "eyJ0eXAiO123V0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		publicKey := &privateKey.PublicKey

		_, err = Parse[*ecdsa.PrivateKey, *ecdsa.PublicKey](check1, publicKey)
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

		parsed, err := Parse[ed25519.PrivateKey, ed25519.PublicKey](tokenString, publicKey)
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
			t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["iat"])
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

		_, err = Parse[ed25519.PrivateKey, ed25519.PublicKey](tokenString, publicKey)
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTMethodInvalid) {
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

		_, err = Parse[ed25519.PrivateKey, ed25519.PublicKey](newTokenString, publicKey)
		if err == nil {
			t.Error("Parse should return error")
		}
		if !errors.Is(err, ErrJWTVerifyFail) {
			t.Errorf("Parse error, got %s, want %s", err, ErrJWTVerifyFail)
		}

	}

}
