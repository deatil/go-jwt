package jwt

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func fromHex(s string) []byte {
	h, _ := hex.DecodeString(s)
	return h
}

func fromBase64(data string) []byte {
	buffer, _ := base64.StdEncoding.DecodeString(data)
	return buffer
}

func toBase64(data []byte) string {
	res := base64.StdEncoding.EncodeToString(data)
	return res
}

func Test_ParsePEM(t *testing.T) {
	d := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----
    `

	res, err := ParsePEM([]byte(d))
	if err != nil {
		t.Fatal(err)
	}

	res2 := toBase64(res)
	check := "MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg=="

	if res2 != check {
		t.Errorf("ParsePEM got %s, want %s", res2, check)
	}

}

func Test_ParsePEM_Error(t *testing.T) {
	d := `
-----BEGINE EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----
    `

	_, err := ParsePEM([]byte(d))
	if err == nil {
		t.Error("ParsePEM should return error")
	}
	if !errors.Is(err, ErrPEMInvalid) {
		t.Errorf("ParsePEM got %s, want %s", err.Error(), ErrPEMInvalid)
	}

}
