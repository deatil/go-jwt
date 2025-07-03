package encoder

import (
	"bytes"
	"testing"
)

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

func Test_Base64URL_Options(t *testing.T) {
	data := []byte("test-pass")

	en, err := NewJoseEncoder().Base64URLEncode(data)
	if err != nil {
		t.Fatal(err)
	}

	de, err := NewJoseEncoder(
		WithStrictDecoding(),
		WithPaddingAllowed(),
	).Base64URLDecode(en)
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

func Test_JSONEncode_Options(t *testing.T) {
	data := map[string]string{
		"key":  "test-pass",
		"key2": "test-pass-JSON",
	}

	en, err := NewJoseEncoder().JSONEncode(data)
	if err != nil {
		t.Fatal(err)
	}

	var deData map[string]string
	err = NewJoseEncoder(WithJSONNumber()).JSONDecode(en, &deData)
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
