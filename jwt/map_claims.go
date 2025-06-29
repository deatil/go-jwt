package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// TimePrecision sets the precision of times and dates within this library.
var TimePrecision = time.Second

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

// NewNumericDate constructs a new *NumericDate from a standard library time.Time struct.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(TimePrecision)}
}

// newNumericDateFromSeconds creates a new *NumericDate out of a float64 representing a
// UNIX epoch with the float fraction representing non-integer seconds.
func newNumericDateFromSeconds(f float64) *NumericDate {
	round, frac := math.Modf(f)
	return NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}

// MapClaims is a claims type that uses the map[string]any for JSON
// decoding. This is the default claims type if you don't supply one
type MapClaims map[string]any

// GetExpirationTime implements the Claims interface.
func (m MapClaims) GetExpirationTime() (*NumericDate, error) {
	return m.parseNumericDate("exp")
}

// GetNotBefore implements the Claims interface.
func (m MapClaims) GetNotBefore() (*NumericDate, error) {
	return m.parseNumericDate("nbf")
}

// GetIssuedAt implements the Claims interface.
func (m MapClaims) GetIssuedAt() (*NumericDate, error) {
	return m.parseNumericDate("iat")
}

// GetAudience implements the Claims interface.
func (m MapClaims) GetAudience() (string, error) {
	return m.parseString("aud")
}

// GetIssuer implements the Claims interface.
func (m MapClaims) GetIssuer() (string, error) {
	return m.parseString("iss")
}

// GetSubject implements the Claims interface.
func (m MapClaims) GetSubject() (string, error) {
	return m.parseString("sub")
}

// GetNumericDate implements the Claims interface.
func (m MapClaims) GetNumericDate(name string) (*NumericDate, error) {
	return m.parseNumericDate(name)
}

// GetString implements the Claims interface.
func (m MapClaims) GetString(name string) (string, error) {
	return m.parseString(name)
}

// parseNumericDate tries to parse a key in the map claims type as a number date.
func (m MapClaims) parseNumericDate(key string) (*NumericDate, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}

	switch exp := v.(type) {
	case int64:
		if exp == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(float64(exp)), nil
	case float64:
		if exp == 0 {
			return nil, nil
		}

		return newNumericDateFromSeconds(exp), nil
	case json.Number:
		v, _ := exp.Float64()

		return newNumericDateFromSeconds(v), nil
	}

	return nil, newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
}

// parseString tries to parse a key in the map claims type as a [string] type.
func (m MapClaims) parseString(key string) (string, error) {
	var (
		ok  bool
		raw any
		iss string
	)
	raw, ok = m[key]
	if !ok {
		return "", nil
	}

	iss, ok = raw.(string)
	if !ok {
		return "", newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
	}

	return iss, nil
}
