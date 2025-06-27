package jwt

import (
	"testing"
)

func Test_Token(t *testing.T) {
	var header = TokenHeader{
		Typ: "JWT",
		Alg: "ES256",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9"
	var check2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = NewToken(NewJoseEncoder())
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

	var token2 = NewToken(NewJoseEncoder())
	token2.Parse(check1)

	header2, err := token2.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header2.Typ != "JWT" {
		t.Errorf("GetHeader type got %s, want %s", header2.Typ, "JWT")
	}
	if header2.Alg != "ES256" {
		t.Errorf("GetHeader Alg got %s, want %s", header2.Alg, "ES256")
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

	var token3 = NewToken(NewJoseEncoder())
	token3.Parse(check2)

	header3, err := token3.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header3.Typ != "JWT" {
		t.Errorf("GetHeader type got %s, want %s", header3.Typ, "JWT")
	}
	if header3.Alg != "ES256" {
		t.Errorf("GetHeader Alg got %s, want %s", header3.Alg, "ES256")
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

	token5 := token3.GetRawNoSignature()
	if token5 != check1 {
		t.Errorf("GetRawNoSignature got %s, want %s", token5, check1)
	}

	// ====================

	check3 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"

	var token6 = NewToken(NewJoseEncoder())
	token6.Parse(check3)

	sig61 := token6.GetRaw()
	if sig61 != check3 {
		t.Errorf("GetRaw got %s, want %s", sig61, check3)
	}

	sig6 := token6.GetRawNoSignature()
	if sig6 != check3 {
		t.Errorf("GetRawNoSignature got %s, want %s", sig6, check3)
	}

}

func Test_Token2(t *testing.T) {
	var header = TokenHeader{
		Typ: "JWE",
		Alg: "ES256",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = NewToken(NewJoseEncoder())
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

	var token2 = NewToken(NewJoseEncoder())
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
	var header = TokenHeader{
		Typ: "JWE",
		Alg: "ES256",
		Kid: "kids",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = NewToken(NewJoseEncoder())
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

	var token2 = NewToken(NewJoseEncoder())
	token2.Parse(check1)

	header2, err := token2.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header2.Kid != header.Kid {
		t.Errorf("GetHeader Kid got %s, want %s", header2.Kid, header.Kid)
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
	if header3.Typ != header.Typ {
		t.Errorf("GetHeadersT Typ got %s, want %s", header3.Typ, header.Typ)
	}
	if header3.Alg != header.Alg {
		t.Errorf("GetHeadersT Alg got %s, want %s", header3.Alg, header.Alg)
	}
	if header3.Kid != header.Kid {
		t.Errorf("GetHeadersT Kid got %s, want %s", header3.Kid, header.Kid)
	}

	header33, err := token2.GetHeaders()
	if err != nil {
		t.Fatal(err)
	}
	if header33["typ"].(string) != header.Typ {
		t.Errorf("GetHeaders Typ got %s, want %s", header33["typ"], header.Typ)
	}
	if header33["alg"].(string) != header.Alg {
		t.Errorf("GetHeaders Alg got %s, want %s", header33["alg"], header.Alg)
	}
	if header33["kid"].(string) != header.Kid {
		t.Errorf("GetHeaders Kid got %s, want %s", header33["kid"], header.Kid)
	}

}

func Test_DefaultToken(t *testing.T) {
	var header = TokenHeader{
		Typ: "JWT",
		Alg: "ES256",
	}
	var claims = map[string]string{
		"aud": "example.com",
		"iat": "foo",
	}
	var signature = "test-signature"

	var check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9"
	var check2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU"

	var token = DefaultToken
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

	var token2 = DefaultToken
	token2.Parse(check1)

	header2, err := token2.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header2.Typ != "JWT" {
		t.Errorf("GetHeader type got %s, want %s", header2.Typ, "JWT")
	}
	if header2.Alg != "ES256" {
		t.Errorf("GetHeader Alg got %s, want %s", header2.Alg, "ES256")
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

	var token3 = DefaultToken
	token3.Parse(check2)

	header3, err := token3.GetHeader()
	if err != nil {
		t.Fatal(err)
	}
	if header3.Typ != "JWT" {
		t.Errorf("GetHeader type got %s, want %s", header3.Typ, "JWT")
	}
	if header3.Alg != "ES256" {
		t.Errorf("GetHeader Alg got %s, want %s", header3.Alg, "ES256")
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

	token5 := token3.GetRawNoSignature()
	if token5 != check1 {
		t.Errorf("GetRawNoSignature got %s, want %s", token5, check1)
	}

	// ====================

	check3 := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"

	var token6 = DefaultToken
	token6.Parse(check3)

	sig61 := token6.GetRaw()
	if sig61 != check3 {
		t.Errorf("GetRaw got %s, want %s", sig61, check3)
	}

	sig6 := token6.GetRawNoSignature()
	if sig6 != check3 {
		t.Errorf("GetRawNoSignature got %s, want %s", sig6, check3)
	}

}
