package encoder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type JoseEncoder struct {
	// Use JSON Number format in JSON decoder.
	useJSONNumber bool

	decodeStrict bool

	decodePaddingAllowed bool
}

func NewJoseEncoder(options ...Options) *JoseEncoder {
	e := &JoseEncoder{}

	// Loop through our parsing options and apply them
	for _, option := range options {
		option(e)
	}

	return e
}

func (e *JoseEncoder) Base64URLEncode(data []byte) (string, error) {
	buffer := base64.RawURLEncoding.EncodeToString(data)
	return buffer, nil
}

func (e *JoseEncoder) Base64URLDecode(data string) ([]byte, error) {
	encoding := base64.RawURLEncoding

	if e.decodePaddingAllowed {
		if l := len(data) % 4; l > 0 {
			data += strings.Repeat("=", 4-l)
		}

		encoding = base64.URLEncoding
	}

	if e.decodeStrict {
		encoding = encoding.Strict()
	}

	return encoding.DecodeString(data)
}

func (e *JoseEncoder) JSONEncode(data any) ([]byte, error) {
	return json.Marshal(data)
}

func (e *JoseEncoder) JSONDecode(data []byte, dst any) error {
	if !e.useJSONNumber {
		return json.Unmarshal(data, dst)
	}

	dec := json.NewDecoder(bytes.NewBuffer(data))
	dec.UseNumber()

	return dec.Decode(dst)
}
