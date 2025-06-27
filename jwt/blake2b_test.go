package jwt

import (
	"fmt"
	"testing"
)

func Test_SigningBLAKE2B(t *testing.T) {
	h := SigningBLAKE2B

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "BLAKE2B" {
		t.Errorf("Alg got %s, want %s", alg, "BLAKE2B")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	var msg = "test-data"
	var key = "12345678901234567890as1234567890"
	var sign = "d40bb120a0915ab65e0051fca93854775bd1380a1fb012ebd5c5df361159937e"

	signed, err := h.Sign([]byte(msg), []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	signature := fmt.Sprintf("%x", signed)
	if signature != sign {
		t.Errorf("Sign got %s, want %s", signature, sign)
	}

	veri, err := h.Verify([]byte(msg), signed, []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	if !veri {
		t.Error("Verify fail")
	}

	{
		signed[5] = signed[5] + 1

		_, err := h.Verify([]byte(msg), signed, []byte(key))
		if err == nil {
			t.Error("Verify should return error")
		}
	}

}

func Test_SigningBLAKE2B_KeyTooShort(t *testing.T) {
	h := SigningBLAKE2B

	alg := h.Alg()
	signLength := h.SignLength()

	if alg != "BLAKE2B" {
		t.Errorf("Alg got %s, want %s", alg, "BLAKE2B")
	}
	if signLength != 32 {
		t.Errorf("SignLength got %d, want %d", signLength, 32)
	}

	var msg = "test-data"
	var key = "test-key"

	_, err := h.Sign([]byte(msg), []byte(key))
	if err == nil {
		t.Error("Parse should return error")
	}

	errcheck := "go-jwt: SignBlake2b key too short"
	if err.Error() != errcheck {
		t.Errorf("Sign Err got %s, want %s", err.Error(), errcheck)
	}
}
