package jwt

import (
    "fmt"
    "testing"
)

func Test_SigningHMD5(t *testing.T) {
    h := SigningHMD5

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "HMD5" {
        t.Errorf("Alg got %s, want %s", alg, "HMD5")
    }
    if signLength != 16 {
        t.Errorf("SignLength got %d, want %d", signLength, 16)
    }

    var msg = "test-data"
    var key = "test-key"
    var sign = "e2e8b98014f740a7c2e19152c24534b2"

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

}

func Test_SigningHSHA1(t *testing.T) {
    h := SigningHSHA1

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "HSHA1" {
        t.Errorf("Alg got %s, want %s", alg, "HSHA1")
    }
    if signLength != 20 {
        t.Errorf("SignLength got %d, want %d", signLength, 20)
    }

    var msg = "test-data"
    var key = "test-key"
    var sign = "4106aea97422ce36d01edb8deb52a7841f0234e5"

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

}

func Test_SigningHS224(t *testing.T) {
    h := SigningHS224

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "HS224" {
        t.Errorf("Alg got %s, want %s", alg, "HS224")
    }
    if signLength != 28 {
        t.Errorf("SignLength got %d, want %d", signLength, 28)
    }

    var msg = "test-data"
    var key = "test-key"
    var sign = "ed6ef737f62e606c28d27a7c586b23becae7196fd4c7b141b46c9902"

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

}

func Test_SigningHS256(t *testing.T) {
    h := SigningHS256

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "HS256" {
        t.Errorf("Alg got %s, want %s", alg, "HS256")
    }
    if signLength != 32 {
        t.Errorf("SignLength got %d, want %d", signLength, 32)
    }

    var msg = "test-data"
    var key = "test-key"
    var sign = "21a286fd6fd9f52676007c66d0f883db46d06158c266d33fb537c23bc618e567"

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

}

func Test_SigningHS384(t *testing.T) {
    h := SigningHS384

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "HS384" {
        t.Errorf("Alg got %s, want %s", alg, "HS384")
    }
    if signLength != 48 {
        t.Errorf("SignLength got %d, want %d", signLength, 48)
    }

    var msg = "test-data"
    var key = "test-key"
    var sign = "7ef9106e87232142b352343c291d323498d8a8426029181ddf61a65d0f1bc2c497c86a1091f66d97c2179a18d6e67bdf"

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

}

func Test_SigningHS512(t *testing.T) {
    h := SigningHS512

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "HS512" {
        t.Errorf("Alg got %s, want %s", alg, "HS512")
    }
    if signLength != 64 {
        t.Errorf("SignLength got %d, want %d", signLength, 64)
    }

    var msg = "test-data"
    var key = "test-key"
    var sign = "080e166f475f1c5d61f26b94d45a0cd822729a525e3a3865b87cdf58a36f039ea1948735aab3ad5027d553ad06487fb57d3a9034d2861300297d6cebf838f5bf"

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

}
