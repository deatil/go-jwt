package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func Test_SigningEdDSA(t *testing.T) {
	h := SigningEdDSA

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "EdDSA" {
		t.Errorf("Alg got %s, want %s", alg, "EdDSA")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	var msg = "test-data"

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

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

func Test_SigningED25519(t *testing.T) {
	h := SigningED25519

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ED25519" {
		t.Errorf("Alg got %s, want %s", alg, "ED25519")
	}
	if signLength != 64 {
		t.Errorf("SignLength got %d, want %d", signLength, 64)
	}

	var msg = "test-data"

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

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

func Test_SigningEdDSA_with_der_key(t *testing.T) {
	h := SigningEdDSA

	var prikey = "MC4CAQAwBQYDK2VwBCIEIE7YvvGJzvKQ3uZOQ6qAPkRsK7nkpmjPOaqsZKqrFQMw"
	var pubkey = "MCowBQYDK2VwAyEAgbbl7UO5W8ZMmOm+Kw9X2y9PyblBTDcZIRaR/kDFoA0="

	var prikeyBytes = fromBase64(prikey)
	var pubkeyBytes = fromBase64(pubkey)

	privateKey, err := ParseEdPrivateKeyFromDer(prikeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := ParseEdPublicKeyFromDer(pubkeyBytes)
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
