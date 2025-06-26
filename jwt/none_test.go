package jwt

import (
    "fmt"
    "testing"
)

func Test_SigningNone(t *testing.T) {
    h := SigningNone

    alg := h.Alg()
    signLength := h.SignLength()

    if alg != "none" {
        t.Errorf("Alg got %s, want %s", alg, "none")
    }
    if signLength != 0 {
        t.Errorf("SignLength got %d, want %d", signLength, 0)
    }

    var msg = "test-data"
    var key = ""
    var sign = ""

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
