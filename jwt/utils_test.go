package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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

func Test_Base64URL(t *testing.T) {
	data := []byte("test-pass")

	en, err := NewJoseEncoder().Base64URLEncode(data)
	if err != nil {
		t.Fatal(err)
	}

	de, err := NewJoseEncoder().Base64URLDecode(en)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, de) != 0 {
		t.Errorf("Decode got %s, want %s", string(de), string(data))
	}
}

func Test_JSONEncode(t *testing.T) {
	data := map[string]string{
		"key":  "test-pass",
		"key2": "test-pass-JSON",
	}

	en, err := NewJoseEncoder().JSONEncode(data)
	if err != nil {
		t.Fatal(err)
	}

	var deData map[string]string
	err = NewJoseEncoder().JSONDecode(en, &deData)
	if err != nil {
		t.Fatal(err)
	}

	if data["key"] != deData["key"] {
		t.Errorf("Decode key got %x, want %x", deData["key"], data["key"])
	}
	if data["key2"] != deData["key2"] {
		t.Errorf("Decode key2 got %x, want %x", deData["key2"], data["key2"])
	}

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
