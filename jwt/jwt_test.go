package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
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
	s.WithRandom(rand.Reader)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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

	alg, _ := header.GetAlgorithm()
	if alg != "ES256" {
		t.Errorf("GetTokenHeader Alg got %s, want %s", alg, "ES256")
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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

	if header2["typ"] != header["typ"] {
		t.Errorf("GetHeaders typ got %s, want %s", header2["typ"], header["typ"])
	}
	if header2["alg"] != header["alg"] {
		t.Errorf("GetHeaders alg got %s, want %s", header2["alg"], header["alg"])
	}
	if header2["tuy"] != header["tuy"] {
		t.Errorf("GetHeaders tuy got %s, want %s", header2["tuy"], header["tuy"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodES256(t *testing.T) {
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
	s.WithRandom(rand.Reader)
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodES512(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	s := SigningMethodES512.New()
	s.WithRandom(rand.Reader)

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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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

	typ, _ := header2.GetType()
	if typ != "" {
		t.Errorf("GetClaims typ got %s", typ)
	}
	alg1, _ := header2.GetAlgorithm()
	if alg1 != header["alg"] {
		t.Errorf("GetClaims alg got %s, want %s", alg1, header["alg"])
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

	privateKey, err := ParseECPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromPEM([]byte(pubkey))
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
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

	privateKey, err := ParseECPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseECPublicKeyFromPEM([]byte(pubkey))
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_GetTokenHeader_WithEncoder(t *testing.T) {
	tokenStr := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ"

	header, err := GetTokenHeader(tokenStr, JWTEncoder)
	if err != nil {
		t.Fatal(err)
	}

	alg, _ := header.GetAlgorithm()
	if alg != "ES256" {
		t.Errorf("GetTokenHeader Alg got %s, want %s", alg, "ES256")
	}

}

func Test_NewJWT_Error(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Error("should throw panic")
		} else {
			checkerr := "go-jwt: Signer invalid"
			if err.(error).Error() != checkerr {
				t.Errorf("NewJWT got %s, want %s", err.(error).Error(), checkerr)
			}
		}
	}()

	_ = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](nil, nil)
}

func Test_NewJWT_Error2(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Error("should throw panic")
		} else {
			checkerr := "go-jwt: Encoder invalid"
			if err.(error).Error() != checkerr {
				t.Errorf("NewJWT got %s, want %s", err.(error).Error(), checkerr)
			}
		}
	}()

	_ = NewJWT[*rsa.PrivateKey, *rsa.PublicKey](SigningRS256, nil)
}

func Test_RegisteredHeaders(t *testing.T) {
	h := RegisteredHeaders{
		Type:        "typ",
		Algorithm:   "algo",
		KeyID:       "kida",
		ContentType: "ctyaa",
	}

	var val string

	val, _ = h.GetType()
	if val != "typ" {
		t.Errorf("GetType got %s, want %s", val, "typ")
	}

	val, _ = h.GetAlgorithm()
	if val != "algo" {
		t.Errorf("GetAlgorithm got %s, want %s", val, "algo")
	}

	val, _ = h.GetKeyID()
	if val != "kida" {
		t.Errorf("GetKeyID got %s, want %s", val, "kida")
	}

	val, _ = h.GetContentType()
	if val != "ctyaa" {
		t.Errorf("GetContentType got %s, want %s", val, "ctyaa")
	}
}

func testEqStr(t *testing.T, e, a string) {
	if e != a {
		t.Errorf("equal got %s, want %s", a, e)
	}
}

func Test_RegisteredsStd(t *testing.T) {
	testEqStr(t, "typ", RegisteredStdHeaders.Type)
	testEqStr(t, "alg", RegisteredStdHeaders.Algorithm)
	testEqStr(t, "kid", RegisteredStdHeaders.KeyID)
	testEqStr(t, "cty", RegisteredStdHeaders.ContentType)
	testEqStr(t, "enc", RegisteredStdHeaders.Encryption)

	testEqStr(t, "aud", RegisteredStdClaims.Audience)
	testEqStr(t, "exp", RegisteredStdClaims.ExpirationTime)
	testEqStr(t, "jti", RegisteredStdClaims.ID)
	testEqStr(t, "iat", RegisteredStdClaims.IssuedAt)
	testEqStr(t, "iss", RegisteredStdClaims.Issuer)
	testEqStr(t, "nbf", RegisteredStdClaims.NotBefore)
	testEqStr(t, "sub", RegisteredStdClaims.Subject)
}

func Test_GetSigner(t *testing.T) {
	p := SigningMethodPS256.New()
	testEqStr(t, "PS256", p.GetSigner().Alg())

	p1 := SigningMethodHS256.New()
	testEqStr(t, "HS256", p1.GetSigner().Alg())

	p2 := SigningMethodES256.New()
	testEqStr(t, "ES256", p2.GetSigner().Alg())
}

func Test_SigningMethodES384_Check_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCKkU3/bJJS2nV+u4FS
gCLgcaNaDnyB7sEEhXvCLf4DJiLWplxb/lNdHKtEVbx828OgBwYFK4EEACKhZANi
AATOXjuGfhl/4JylsxuaEw4fxIOXle0hJD1AJODcC8e3KJSMG5MGhKLQPvo2IZAd
9IK7byRArzegzwtMjAnGzE9oIXnCm7JczuyX4sRPoL8d+RNtc7ZVjEL/srgTWohW
A3s=
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzl47hn4Zf+CcpbMbmhMOH8SDl5XtISQ9
QCTg3AvHtyiUjBuTBoSi0D76NiGQHfSCu28kQK83oM8LTIwJxsxPaCF5wpuyXM7s
l+LET6C/HfkTbXO2VYxC/7K4E1qIVgN7
-----END PUBLIC KEY-----
    `
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.GeAljd7NH1LQ363xqAb7G608EvXX3svYTMwjcmEVnTapGF7Y4puGIVW4TeXsMij9646Gi_HJ3ghAqgHvWh5CMyvQFOQThyVy7CVxhtrn3GFgse1Kz8wOd0_X_XtOvCsF"

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

func Test_SigningMethodES512_Check_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIAyYKP3zmWUSvKgv9B
YFSQ8SNvCUWQ+ac4o8xxVxQ0xJJYi5r86HoOcPafRhA08FpL5QsbH09t7SIb4/u3
SRoaHamgBwYFK4EEACOhgYkDgYYABAHlKXMgRKArgvYmeANJpFSbOlD51GpU/jnQ
zhWoomjv4MT/Urz4tTzkMY1gWNIpMFNYKzczdT6QWcaCvYx80fN20ACwZYQpDhb4
lAo3rKovPU5wBzwGfMDMX3WYaPCglREuk1mV13TLW5xsv0SbKOoHQuaGiQ8Vb2W0
QQwS8iecuQQq8g==
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB5SlzIESgK4L2JngDSaRUmzpQ+dRq
VP450M4VqKJo7+DE/1K8+LU85DGNYFjSKTBTWCs3M3U+kFnGgr2MfNHzdtAAsGWE
KQ4W+JQKN6yqLz1OcAc8BnzAzF91mGjwoJURLpNZldd0y1ucbL9EmyjqB0LmhokP
FW9ltEEMEvInnLkEKvI=
-----END PUBLIC KEY-----
    `
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AdHc_BALB2aBPnEl0FLQtOLgJLqmbxgF9npNd19TZTYwqHmZZ0_eizbagmjJVxpImzXSi-DYezLQDbwN_4iJrvlxAILX9SSrsHh0zbkJAjMAIJDMkZ7nfR7KgCNqvyT7JgEN41i6juk1n8uP3edFptYa1QxnLEG4v6_-NJdOl1xQVtZA"

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

func Test_SigningMethodEdDSA_Check_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIK3jWwBPmk1J4dynA3CjSfOLP9seazHZYZ6MCqCU+n0f
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAj/CWF9RnNKe/L0jHWHpUICXDowaNYLbj7Ck/wdzTvE4=
-----END PUBLIC KEY-----
    `
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJmb28iOiJiYXIifQ.AMI_8S4nuqBQ8Y7MLrU_iyDXDJcd651Y7eDR3AO98tfDGKkkp2MJj-yQoZzdbjeYrl3ocotlmor3Otwf1PUbCQ"

	privateKey, err := ParseEdPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseEdPublicKeyFromPEM([]byte(pubkey))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodEdDSA.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodEdDSA.New()
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

func Test_SigningMethodRS256_From_PEM(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdr
j8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aY
w9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQ
tzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2B
rClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2Xr
HhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohB
TSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARd
pd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIB
AQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQ
G3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7
hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGj
ZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah
1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazK
rtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvab
DDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/nj
xIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/
gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/
nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQ
ghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNq
ibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjt
u0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlg
hFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bg
t1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+j
rAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O9
98BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86Eunfd
PuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5W
K3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+
s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aV
bbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckbm
DgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6
drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj
4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dn
cdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS
9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jp
dbL83Fbq
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rF
kEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mC
pz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZ
tDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn
/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpY
VaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1
AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5L
dYKtznTuy7wIDAQAB
-----END PUBLIC KEY-----
    `

	privateKey, err := ParseRSAPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromPEM([]byte(pubkey))
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
		t.Errorf("GetClaims sub got %s, want %s", claims2["sub"].(string), claims["sub"])
	}

}

func Test_SigningMethodRS256_Check_With_PEM_pkcs8_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdr
j8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aY
w9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQ
tzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2B
rClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2Xr
HhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohB
TSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARd
pd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIB
AQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQ
G3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7
hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGj
ZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah
1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazK
rtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvab
DDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/nj
xIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/
gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/
nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQ
ghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNq
ibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjt
u0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlg
hFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bg
t1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+j
rAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O9
98BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86Eunfd
PuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5W
K3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+
s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aV
bbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckbm
DgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6
drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj
4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dn
cdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS
9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jp
dbL83Fbq
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rF
kEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mC
pz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZ
tDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn
/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpY
VaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1
AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5L
dYKtznTuy7wIDAQAB
-----END PUBLIC KEY-----
    `
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg"

	privateKey, err := ParseRSAPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseRSAPublicKeyFromPEM([]byte(pubkey))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodRS256.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
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

	if claims2["foo"].(string) != claims["foo"] {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), claims["foo"])
	}

}

func Test_SigningMethodPS256_Check2(t *testing.T) {
	var pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"
	var tokenStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.GIXxlCsbPsCVLyJdGVL0mz5Yg_40HEZSZIQwgdc02sPAnMfy29ZbbWCt5PAyv8KkbLZPx4kTgYwANhVm4_ggUJ25HARteMJBMbS-bxXlYlxjMxNy6yFj5unqQLicjCrQaN1UOw5GTmBjVssqQtTuZnlMduECq7uorsn5QoqIK3z01kiWjWpdo_SKJJ2Afeg0SqY7rx5jH_QVTLIzyuoMahQ8hDsqjcFjku2ncbZ3I0oJ0IZsiWxF21TmjxZRkPTe1LtYLSF_gaWucYJU_YOm5OWnlXjywMFq0ItQEUXMxO9OxUGjkISiAdUNwHkNRyZBFhmFmHjjMX8EPKsY99AAaw"

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

	check := "joe"
	if claims2["iss"].(string) != check {
		t.Errorf("GetClaims foo got %s, want %s", claims2["foo"].(string), check)
	}

}

func Test_SigningMethodMLDSA44(t *testing.T) {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	s := SigningMethodMLDSA44.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodMLDSA44.New()
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

func Test_SigningMethodMLDSA65(t *testing.T) {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	s := SigningMethodMLDSA65.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodMLDSA65.New()
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

func Test_SigningMethodMLDSA87(t *testing.T) {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	s := SigningMethodMLDSA87.New()

	claims := map[string]string{
		"aud": "example.com",
		"sub": "foo",
	}

	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodMLDSA87.New()
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

func Test_SigningMethodMLDSA65_fail(t *testing.T) {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	{
		claims := map[string]string{
			"aud": "example.com",
			"sub": "foo",
		}

		s := SigningMethodMLDSA87.New()
		_, err := s.Sign(claims, privateKey)
		if !errors.Is(err, ErrSignMLDSAParametersInvalid) {
			t.Fatal("SigningMethodMLDSA87 Sign error fail")
		}
	}

	{
		claims := map[string]string{
			"aud": "example.com",
			"sub": "foo",
		}

		s := SigningMethodMLDSA65.New()
		tokenString, err := s.Sign(claims, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		p := SigningMethodMLDSA87.New()
		_, err = p.Parse(tokenString, publicKey)
		if !errors.Is(err, ErrJWTAlgoInvalid) {
			t.Fatalf("SigningMethodMLDSA87 Parse error fail, %s", err)
		}
	}

}

func Test_SigningMethodMLDSA44_Check(t *testing.T) {
	var pubkey = "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ"
	var tokenStr = "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujXVJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMhJthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khOqwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_DTiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrxf94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCzv53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv744VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20DwDBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKDTRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Yo3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaOKgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIfMEQ"

	var pubkeyBytes = fromUrlBase64(pubkey)

	publicKey, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodMLDSA44.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2 := parsed.GetHeaderRaw()
	check1 := `{"alg":"ML-DSA-44","kid":"T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o"}`
	if string(header2) != check1 {
		t.Errorf("GetHeaderRaw() raw got %s, want %s", string(header2), check1)
	}

	claims2 := parsed.GetClaimsRaw()
	check := "It’s a dangerous business, Frodo, going out your door."
	if string(claims2) != check {
		t.Errorf("GetClaimsRaw() raw got %s, want %s", string(claims2), check)
	}

	// =====

	var tokenStr2 = "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujXVJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMhJthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khOqwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_DTiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrxf94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCzv53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv744VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20DwDBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKDTRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Yo3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaOKgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIf111"

	_, err = p.Parse(tokenStr2, publicKey)
	if err == nil {
		t.Fatal("should return error")
	}
}

func Test_SigningMethodMLDSA65_Check(t *testing.T) {
	var pubkey = "QksvJn5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9NmfmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBks23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIurcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLBB3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51pljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7wZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjxclmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUdm-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJUUBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UNwwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJqZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFYHhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0BZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJbXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTEyRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1MEZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsyW1Juo"
	var tokenStr = "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfRo4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5orKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjtGOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnxsvBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqrVcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFNfMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QOnkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJLmmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06ExdzBhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwIHfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaMyBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoWTr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwMArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZCHd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37sKKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gtL-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDphbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHtsXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRdxCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAclxcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOXPATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJaJGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV21QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVSDBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJJ3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_86zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZljCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zorTWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMfz8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0fnrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZEzNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVHCUv"

	var pubkeyBytes = fromUrlBase64(pubkey)

	publicKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodMLDSA65.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2 := parsed.GetHeaderRaw()
	check1 := `{"alg":"ML-DSA-65","kid":"Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM"}`
	if string(header2) != check1 {
		t.Errorf("GetHeaderRaw() raw got %s, want %s", string(header2), check1)
	}

	claims2 := parsed.GetClaimsRaw()
	check := "It’s a dangerous business, Frodo, going out your door."
	if string(claims2) != check {
		t.Errorf("GetClaimsRaw() raw got %s, want %s", string(claims2), check)
	}

	// =====

	var tokenStr2 = "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfRo4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5orKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjtGOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnxsvBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqrVcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFNfMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QOnkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJLmmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06ExdzBhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwIHfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaMyBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoWTr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwMArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZCHd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37sKKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gtL-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDphbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHtsXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRdxCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAclxcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOXPATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJaJGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV21QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVSDBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJJ3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_86zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZljCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zorTWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMfz8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0fnrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZEzNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVH111"

	_, err = p.Parse(tokenStr2, publicKey)
	if err == nil {
		t.Fatal("should return error")
	}
}

func Test_SigningMethodMLDSA87_Check(t *testing.T) {
	var pubkey = "5F_8jMc9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73envj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6bylPM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXovda4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAgkE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61CyyrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuDxMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUfrJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8msb8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOte0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbCH2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPky75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHUryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjfIC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g817bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHlsb8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DNEgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bemWqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0cBIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwUemXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaCPoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0othfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxmk4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFhM9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_nuLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj"
	var tokenStr = "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXUVq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaLlODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJDBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrANbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmAaDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEUUTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VUGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQyiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlAX56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHmFUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvplwcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXrupgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0OnA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qbC6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NXp06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYvEztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1ASBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLthfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCiq29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSlXYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWnrQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sfAERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43TfyYhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIscdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNuVk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIPhOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3avUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb47LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsquEt7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0BdckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEcuVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0qTa4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI05IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAlKzg7Qw"

	var pubkeyBytes = fromUrlBase64(pubkey)

	publicKey, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	p := SigningMethodMLDSA87.New()
	parsed, err := p.Parse(tokenStr, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	header2 := parsed.GetHeaderRaw()
	check1 := `{"alg":"ML-DSA-87","kid":"tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU"}`
	if string(header2) != check1 {
		t.Errorf("GetHeaderRaw() raw got %s, want %s", string(header2), check1)
	}

	claims2 := parsed.GetClaimsRaw()
	check := "It’s a dangerous business, Frodo, going out your door."
	if string(claims2) != check {
		t.Errorf("GetClaimsRaw() raw got %s, want %s", string(claims2), check)
	}

	// =====

	var tokenStr2 = "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXUVq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaLlODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJDBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrANbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmAaDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEUUTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VUGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQyiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlAX56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHmFUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvplwcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXrupgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0OnA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qbC6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NXp06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYvEztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1ASBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLthfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCiq29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSlXYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWnrQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sfAERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43TfyYhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIscdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNuVk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIPhOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3avUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb47LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsquEt7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0BdckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEcuVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0qTa4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI05IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAlKzg111"

	_, err = p.Parse(tokenStr2, publicKey)
	if err == nil {
		t.Fatal("should return error")
	}

}

func Test_SigningMethodMLDSA44_With_PEM_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIPBmiRIBWe97N3Ilbp37aFah7jNzvMbhJsWq
viXrcfzP
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhACy1v7qduwKMRYFy3xwYzRCOX00e64AHP/ps
TVfYeJVIFemX6CIiyXwV6qCanbT6hLfQqMs6+G3OZBjEj5zLvS6Eu/iAE2x445rm
GBe3iHdLpJiwyRe1xg6L4CGEqjd8vwVaTI/jCruH7hAx6VbtnjZQcwnW5uC23UIu
Fje16NvgTMNzntf3OEaKeu34KsWcXhl5FBjcZUGJlEYE6+WRcT8/1RukCE4o1OqM
Espj88l0VkMclNn+kdeZAhwh8hAle8u+VrvUZqX+Wr6sySXysPbXjK7s2vYZOIai
Wj8rvjcdoHdHgkWFjq82BnSkvL2X5pQvW+XGj4pNMFOWH8hHEqPABe3xyBJL+4EO
4mVl1A7PfYLxE1zqoTZB+Zccti4B5dPYZvw6jNYHbeTOhREVKsFzgJ+YsKbYictU
Zpdl8bZwCGXGPssSvcXF9HDEC42pwNK1niyz1pERZS6lAJMYflT64mkuwKPsWnZz
VIG3VkVRdtsbRjzb6rmGFKk5H0GBxadpt0RIC++csBVTcDQhRrJck204BMpPrVyc
SRFhzfu35n3i1Yow39H3dyrr0odSaVYVhA3lOXoofcswlz68SIOkab/jiqz4Ts6X
2UPtgCJlxa0B/Bkq+7siYvDIL1iOykJwPunWILtw6bFzFsnDwxbvjOzbff1Jfkv7
J284UiO95cbvgtkEij8aJQN56zAcoxfs4X5pYGiNPpYePRrMNYZqndl3+if9bdkh
66lRVDUxeMJY29vSXuFaojHEebyJMrBpwZeoUBJJYzTol2He0+g9u6d1inbjlVT+
9E/XP0lEkKfUhdkdyLM9x19YdxcFx99HLz5KOuy/B1kbru8Xs+GVuyveVzwNWsyf
Z13wljKTtdpU2tDn6jlS3KJ7Dt5QtQfHXirncwNWTGUPk2E5ZTRMgtRhUyXoK+y0
adVSmzPvBn+hPoO5uR4zPpIMXdIuPyv9wVknVbch3txLrkNIPf8NZ+YyQvgki8Aa
sIep3zq8B0amVs4F9c9mKSAuGwXRNtmjHiWsfFZ7CS4BjiRNXTnT8iLH1tSRl4nM
oZVGLntsgpGPYH+d/xYRWAxOZKD++tpNGGM0iVqBwqQM6OwiqT4vhx6GQFObEb8a
lvTfvT6hQ/BBUnVjT5YF4L46hphJ+iW9/cBVgWdkGkbYUvbxsk3wTuqsj7J4mdgg
LqqwCAcNFdLu/9Qw40t83rZXSYESK91d2oeZTTvCUqcTedI31ZEs8gbTMZfjfAOZ
1+S4H3ZtWS16+CclOP5DpTaxcNmTkz8Mo8wAhRV699Gt6FYaEhZWzmpNRcnnflRu
0tjT+SvvIv6HgJr6NsLtio41+31aJuKh9AV2BG2Udmo0CW2GJCYvDxEjzxEgRLZX
gD3OvZrnkXg1Zx+Ww6sdLpqITZkiT6GkJWkpLxVWktIr5qrz2YTL5kCu+stxfafz
Ec4tyETlNrZ18F/BLIzYmJvYNB/A3nK3ftEFSyDhy2b+INumOWJzD96uecv0uysn
WMP92vvMit8B5/d90esXr2qrTYs5CAiJmQbA+n25J+5VIc6jFTWIV4gO668EK4FL
hNldKjrHB/fh8BfVQU+Qfmz2XKH+VPjyulbSI/cthvY6c794e6DOrPg3O6jOGp1M
FVsfMcw/pXHORkapnOWsKpgaezLQEVUiRWhcxRKwSPPj0C4m9bO17MufszVsxAOm
worZNNVd5CeKwC1LV/plg6fhSWhfkqycXQIu8013n5Gviit5+FY=
-----END PUBLIC KEY-----
    `

	privateKey, err := ParseMLDSAPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseMLDSAPublicKeyFromPEM([]byte(pubkey))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodMLDSA44.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodMLDSA44.New()
	parsed, err := p.Parse(tokenString, publicKey)
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

func Test_SigningMethodMLDSA65_With_PEM_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIBbRB15gndF8gEtIQokaAYvOTNfW9a5U3mth
qjNJjkVN
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
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
d7I9IbCD
-----END PUBLIC KEY-----
    `

	privateKey, err := ParseMLDSAPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseMLDSAPublicKeyFromPEM([]byte(pubkey))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodMLDSA65.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodMLDSA65.New()
	parsed, err := p.Parse(tokenString, publicKey)
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

func Test_SigningMethodMLDSA87_With_PEM_Key(t *testing.T) {
	var prikey = `
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMTBCKAIJyDndFRrRdpmTm4biGGzJGW6DGvhGkkDnGd
Rnsu6kFm
-----END PRIVATE KEY-----
    `
	var pubkey = `
-----BEGIN PUBLIC KEY-----
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
3NeJMfdkxY6CRHhgYoXaMa2SEpTzHA==
-----END PUBLIC KEY-----
    `

	privateKey, err := ParseMLDSAPrivateKeyFromPEM([]byte(prikey))
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseMLDSAPublicKeyFromPEM([]byte(pubkey))
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"foo": "bar",
	}

	s := SigningMethodMLDSA87.New()
	tokenString, err := s.Sign(claims, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tokenString) == 0 {
		t.Errorf("Sign length got %d", len(tokenString))
	}

	p := SigningMethodMLDSA87.New()
	parsed, err := p.Parse(tokenString, publicKey)
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
