package jwt

import (
	"fmt"
)

// MapHeaders is a headers type that uses the map[string]any for JSON
// decoding. This is the default headers type if you don't supply one
type MapHeaders map[string]any

func (m MapHeaders) GetType() (string, error) {
	return m.parseString("typ")
}

func (m MapHeaders) GetAlgorithm() (string, error) {
	return m.parseString("alg")
}

func (m MapHeaders) GetKeyID() (string, error) {
	return m.parseString("kid")
}

func (m MapHeaders) GetContentType() (string, error) {
	return m.parseString("cty")
}

func (m MapHeaders) GetString(name string) (string, error) {
	return m.parseString(name)
}

// parseString tries to parse a key in the map headers type as a [string] type.
func (m MapHeaders) parseString(key string) (string, error) {
	var (
		ok   bool
		raw  any
		data string
	)
	raw, ok = m[key]
	if !ok {
		return "", nil
	}

	data, ok = raw.(string)
	if !ok {
		return "", NewError(fmt.Sprintf("%s is invalid", key), ErrJWTHeaderInvalidType)
	}

	return data, nil
}
