package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func Test_SigningES256(t *testing.T) {
	h := SigningES256

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ES256" {
		t.Errorf("Alg got %s, want %s", alg, "ES256")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	var msg = "test-data"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES384(t *testing.T) {
	h := SigningES384

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ES384" {
		t.Errorf("Alg got %s, want %s", alg, "ES384")
	}
	if signLength != 96 {
		t.Errorf("SignLength got %d, want %d", signLength, 96)
	}

	var msg = "test-data"

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES512(t *testing.T) {
	h := SigningES512

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ES512" {
		t.Errorf("Alg got %s, want %s", alg, "ES512")
	}
	if signLength != 132 {
		t.Errorf("SignLength got %d, want %d", signLength, 132)
	}

	var msg = "test-data"

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES256_with_der_key(t *testing.T) {
	h := SigningES256

	var prikey = "MHcCAQEEIEhYoZNv+yhRKnM2+SCgUzi9qH9dWM4MrqMQAKGOpqdpoAoGCCqGSM49AwEHoUQDQgAE9mdkEmwCjAkiIpa+MyWK7LqwZZWMv2Ft6eNXAKIFAaY11SaJBqLYIVCzewGQv/7yKkChKBDx6dvgfxR0Qm2EKw=="
	var pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9mdkEmwCjAkiIpa+MyWK7LqwZZWMv2Ft6eNXAKIFAaY11SaJBqLYIVCzewGQv/7yKkChKBDx6dvgfxR0Qm2EKw=="

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

	var msg = "test-data"

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES256_with_pkcs8_der_key(t *testing.T) {
	h := SigningES256

	var prikey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYwnjpvkTGLLhlf+eJ0XdvbW975d4Y0ntypkpzuvfBL2gCgYIKoZIzj0DAQehRANCAAQwgtPll6KemOFTbbsjt2IohhDKpXVQ5O14hDjHmWd7hWKBn5pFQGqF3OVz6ulEShHYDOgEm8Sd4jRglFtYyRhI"
	var pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMILT5ZeinpjhU227I7diKIYQyqV1UOTteIQ4x5lne4VigZ+aRUBqhdzlc+rpREoR2AzoBJvEneI0YJRbWMkYSA=="

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

	var msg = "test-data"

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES256_with_pkcs8_der_key_no_namedcurve(t *testing.T) {
	h := SigningES256

	var prikey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg02WpZ4lQaQM/PVRB7d4owkuvsuXxrj5vDji8I9zhwNehRANCAAT8yE4hP7yvCEOtDd49SGio7MHlgWd4E6SyCD/HJ0avZVuRkXVobTz6DROHtbuv8EEVuJ/QMQRDxtLVDXAXSYOm"
	var pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/MhOIT+8rwhDrQ3ePUhoqOzB5YFneBOksgg/xydGr2VbkZF1aG08+g0Th7W7r/BBFbif0DEEQ8bS1Q1wF0mDpg=="

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

	var msg = "test-data"

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES384_with_der_key(t *testing.T) {
	h := SigningES384

	var prikey = "MIGkAgEBBDDqWgdCzllebram3uEH+cbKAjsu5xHwL/kZa97cfTJVdZ4j+IMj99PHZkdfxli2vo2gBwYFK4EEACKhZANiAAS5Zzmt6BAsk5mfpCqYBXK3PVy8Vgvkof3+8XLoRpq04PjnwLtdtY/M5pnMxsyWbIRbZHtB8Qkeb71EF+jg7WAtb9B013H1rvlbtVXu0uCmUE3J8hQ3EqY6ugmwqUUhi0M="
	var pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuWc5regQLJOZn6QqmAVytz1cvFYL5KH9/vFy6EaatOD458C7XbWPzOaZzMbMlmyEW2R7QfEJHm+9RBfo4O1gLW/QdNdx9a75W7VV7tLgplBNyfIUNxKmOroJsKlFIYtD"

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

	var msg = "test-data"

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_SigningES384_with_pkcs8_der_key(t *testing.T) {
	h := SigningES384

	var prikey = "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDBzeDiOINSYF7z6egMEwI8qhBIhJYnVE3ShVdjkuYXg68PlRdWHuX+CEYIvxxpKlSWgBwYFK4EEACKhZANiAATQsy+6e9r88AuK1JBLC9URXg6ErKA3s2WoHM4LorWFmZl6klPlB+9k/hhjQWqt4GpRqBZV8Zhp2KXcthY2TdNDbrtMwv/zKZ+pSsugZo13wwLIX8i1h3SHLt4BoCTapUE="
	var pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE0LMvunva/PALitSQSwvVEV4OhKygN7NlqBzOC6K1hZmZepJT5QfvZP4YY0FqreBqUagWVfGYadil3LYWNk3TQ267TML/8ymfqUrLoGaNd8MCyF/ItYd0hy7eAaAk2qVB"

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

	var msg = "test-data"

	signed, err := h.Sign([]byte(msg), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	veri, err := h.Verify([]byte(msg), signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

}

func Test_ParseECKeyFromDer(t *testing.T) {
	var prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq"
	var pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB"

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	_, err := ParseECPrivateKeyFromDer(prikeyBytes)
	if err == nil {
		t.Error("ParseECPrivateKeyFromDer should return error")
	}

	_, err = ParseECPublicKeyFromDer(pubkeyBytes)
	if err == nil {
		t.Error("ParseECPublicKeyFromDer should return error")
	}
}
