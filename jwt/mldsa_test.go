package jwt

import (
	"crypto/mldsa"
	"crypto/rand"
	"testing"
)

func Test_SigningMLDSA44(t *testing.T) {
	h := SigningMLDSA44

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ML-DSA-44" {
		t.Errorf("Alg got %s, want %s", alg, "ML-DSA-44")
	}
	if signLength != 2420 {
		t.Errorf("SignLength got %d, want %d", signLength, 2420)
	}

	var msg = "test-data"

	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	signed, err := h.Sign(rand.Reader, []byte(msg), privateKey)
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

func Test_SigningMLDSA65(t *testing.T) {
	h := SigningMLDSA65

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ML-DSA-65" {
		t.Errorf("Alg got %s, want %s", alg, "ML-DSA-65")
	}
	if signLength != 3309 {
		t.Errorf("SignLength got %d, want %d", signLength, 3309)
	}

	var msg = "test-data"

	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	signed, err := h.Sign(rand.Reader, []byte(msg), privateKey)
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

func Test_SigningMLDSA87(t *testing.T) {
	h := SigningMLDSA87

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "ML-DSA-87" {
		t.Errorf("Alg got %s, want %s", alg, "ML-DSA-87")
	}
	if signLength != 4627 {
		t.Errorf("SignLength got %d, want %d", signLength, 4627)
	}

	var msg = "test-data"

	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}

	publicKey := privateKey.PublicKey()

	signed, err := h.Sign(rand.Reader, []byte(msg), privateKey)
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
