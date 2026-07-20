package jwt

import (
	"testing"
)

func Test_Token(t *testing.T) {
	var header = RegisteredHeaders{
		Type:      "JWT",
		Algorithm: "ES256",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9"
	var check2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = NewToken(JWTEncoder)
	token.SetHeader(header)
	token.SetClaims(claims)
	token.WithSignature([]byte(signature))

	res1, err := token.SigningString()
	if err != nil {
		t.Fatal(err)
	}
	if res1 != check1 {
		t.Errorf("SigningString got %s, want %s", res1, check1)
	}

	res2, err := token.SignedString()
	if err != nil {
		t.Fatal(err)
	}
	if res2 != check2 {
		t.Errorf("SignedString got %s, want %s", res2, check2)
	}

	// ====================

	var token2 = NewToken(JWTEncoder)
	token2.Parse(check1)

	if token2.GetPartCount() != 2 {
		t.Errorf("GetPartCount got %d, want %s", token2.GetPartCount(), "2")
	}

	header2, err := token2.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	typ, _ := header2.GetType()
	if typ != "JWT" {
		t.Errorf("GetHeader type got %s, want %s", typ, "JWT")
	}
	alg, _ := header2.GetAlgorithm()
	if alg != "ES256" {
		t.Errorf("GetHeader Alg got %s, want %s", alg, "ES256")
	}

	claims2, err := token2.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims2["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims2["aud"].(string), claims["aud"])
	}
	if claims2["iat"].(string) != claims["iat"] {
		t.Errorf("GetClaims iat got %s, want %s", claims2["iat"].(string), claims["iat"])
	}

	signature2 := token2.GetSignature()
	if len(signature2) != 0 {
		t.Errorf("GetSignature must %d", 0)
	}

	// ====================

	var token3 = NewToken(JWTEncoder)
	token3.Parse(check2)

	if token3.GetPartCount() != 3 {
		t.Errorf("GetPartCount got %d, want %s", token3.GetPartCount(), "3")
	}

	header3, err := token3.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	typ22, _ := header3.GetType()
	if typ22 != "JWT" {
		t.Errorf("GetHeader type got %s, want %s", typ22, "JWT")
	}
	alg22, _ := header3.GetAlgorithm()
	if alg22 != "ES256" {
		t.Errorf("GetHeader Alg got %s, want %s", alg22, "ES256")
	}

	claims3, err := token3.GetClaims()
	if err != nil {
		t.Fatal(err)
	}

	if claims3["aud"].(string) != claims["aud"] {
		t.Errorf("GetClaims aud got %s, want %s", claims3["aud"].(string), claims["aud"])
	}
	if claims3["iat"].(string) != claims["iat"] {
		t.Errorf("GetClaims iat got %s, want %s", claims3["iat"].(string), claims["iat"])
	}

	signature3 := token3.GetSignature()
	if string(signature3) != signature {
		t.Errorf("GetSignature got %s, want %s", string(signature3), signature)
	}

	token51 := token3.GetRaw()
	if token51 != check2 {
		t.Errorf("GetRaw got %s, want %s", token51, check2)
	}

	token5 := token3.GetMsg()
	if token5 != check1 {
		t.Errorf("GetMsg got %s, want %s", token5, check1)
	}

	// ====================

	check3 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"

	var token6 = NewToken(JWTEncoder)
	token6.Parse(check3)

	sig61 := token6.GetRaw()
	if sig61 != check3 {
		t.Errorf("GetRaw got %s, want %s", sig61, check3)
	}

	sig6 := token6.GetMsg()
	if sig6 != check3 {
		t.Errorf("GetMsg got %s, want %s", sig6, check3)
	}

}

func Test_Token2(t *testing.T) {
	var header = RegisteredHeaders{
		Type:      "JWE",
		Algorithm: "ES256",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = NewToken(JWTEncoder)
	token.SetHeader(header)
	token.SetClaims(claims)
	token.WithSignature([]byte(signature))

	res1, err := token.SignedString()
	if err != nil {
		t.Fatal(err)
	}
	if res1 != check1 {
		t.Errorf("SignedString got %s, want %s", res1, check1)
	}

	// ======

	var token2 = NewToken(JWTEncoder)
	token2.WithHeader([]byte("ase123"))
	token2.WithClaims([]byte("tyh78"))
	token2.WithSignature([]byte("qwe"))

	if string(token2.header) != "ase123" {
		t.Errorf("NewToken header got %s, want %s", string(token2.header), "ase123")
	}
	if string(token2.claims) != "tyh78" {
		t.Errorf("NewToken claims got %s, want %s", string(token2.claims), "tyh78")
	}
	if string(token2.signature) != "qwe" {
		t.Errorf("NewToken signature got %s, want %s", string(token2.signature), "qwe")
	}

}

func Test_Token3(t *testing.T) {
	var header = RegisteredHeaders{
		Type:      "JWE",
		Algorithm: "ES256",
		KeyID:     "kids",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = NewToken(JWTEncoder)
	token.SetHeader(header)
	token.SetClaims(claims)
	token.WithSignature([]byte(signature))

	res1, err := token.SignedString()
	if err != nil {
		t.Fatal(err)
	}
	if res1 != check1 {
		t.Errorf("SignedString got %s, want %s", res1, check1)
	}

	// ======

	var token2 = NewToken(JWTEncoder)
	token2.Parse(check1)

	header2, err := token2.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := header2.GetKeyID()
	if kid != header.KeyID {
		t.Errorf("GetHeader Kid got %s, want %s", kid, header.KeyID)
	}

	// ================

	headerRaw := token2.GetHeaderRaw()
	headerRawCheck := `{"typ":"JWE","alg":"ES256","kid":"kids"}`
	if string(headerRaw) != headerRawCheck {
		t.Errorf("GetHeaderRaw() got %s, want %s", string(headerRaw), headerRawCheck)
	}

	claimsRaw := token2.GetClaimsRaw()
	claimsRawCheck := `{"aud":"example.com","iat":"foo"}`
	if string(claimsRaw) != claimsRawCheck {
		t.Errorf("GetClaimsRaw() got %s, want %s", string(claimsRaw), claimsRawCheck)
	}

	// ================

	type claimsT struct {
		Aud string
		Iat string
	}

	var claims3 claimsT
	err = token2.GetClaimsT(&claims3)
	if err != nil {
		t.Fatal(err)
	}
	if claims3.Aud != claims["aud"] {
		t.Errorf("GetClaimsT aud got %s, want %s", claims3.Aud, claims["aud"])
	}
	if claims3.Iat != claims["iat"] {
		t.Errorf("GetClaimsT Iat got %s, want %s", claims3.Iat, claims["iat"])
	}

	type headerT struct {
		Typ string
		Alg string
		Kid string
	}

	var header3 headerT
	err = token2.GetHeadersT(&header3)
	if err != nil {
		t.Fatal(err)
	}
	if header3.Typ != header.Type {
		t.Errorf("GetHeadersT Typ got %s, want %s", header3.Typ, header.Type)
	}
	if header3.Alg != header.Algorithm {
		t.Errorf("GetHeadersT Alg got %s, want %s", header3.Alg, header.Algorithm)
	}
	if header3.Kid != header.KeyID {
		t.Errorf("GetHeadersT Kid got %s, want %s", header3.Kid, header.KeyID)
	}

	header33, err := token2.GetHeaders()
	if err != nil {
		t.Fatal(err)
	}
	if header33["typ"] != header.Type {
		t.Errorf("GetHeaders Typ got %s, want %s", header33["typ"], header.Type)
	}
	if header33["alg"] != header.Algorithm {
		t.Errorf("GetHeaders Alg got %s, want %s", header33["alg"], header.Algorithm)
	}
	if header33["kid"] != header.KeyID {
		t.Errorf("GetHeaders Kid got %s, want %s", header33["kid"], header.KeyID)
	}

}

func Test_Token5(t *testing.T) {
	check3 := ""

	var token6 = NewToken(JWTEncoder)
	token6.Parse(check3)

	sig61 := token6.GetRaw()
	if len(sig61) > 0 {
		t.Error("GetRaw should empty")
	}

	if sig61 != check3 {
		t.Errorf("GetRaw got %s, want %s", sig61, check3)
	}

}
