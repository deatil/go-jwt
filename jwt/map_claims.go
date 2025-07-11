package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
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

// MarshalJSON is an implementation of the json.RawMessage interface and serializes the UNIX epoch
// represented in NumericDate to a byte array, using the precision specified in TimePrecision.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	var prec int
	if TimePrecision < time.Second {
		prec = int(math.Log10(float64(time.Second) / float64(TimePrecision)))
	}
	truncatedDate := date.Truncate(TimePrecision)

	seconds := strconv.FormatInt(truncatedDate.Unix(), 10)
	nanosecondsOffset := strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', prec, 64)

	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)

	return output, nil
}

// UnmarshalJSON is an implementation of the json.RawMessage interface and
// deserializes a [NumericDate] from a JSON representation, i.e. a
// [json.Number]. This number represents an UNIX epoch with either integer or
// non-integer seconds.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var number json.Number
	var val float64

	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericData: %w", err)
	}

	if val, err = number.Float64(); err != nil {
		return fmt.Errorf("could not convert json number value to float: %w", err)
	}

	n := newNumericDateFromSeconds(val)
	*date = *n

	return nil
}

// ClaimStrings is basically just a slice of strings, but it can be either
// serialized from a string array or just a string. This type is necessary,
// since the "aud" claim can either be a single string or an array.
type ClaimStrings struct {
	Value    []string
	AsString bool
}

// NewClaimStrings constructs a new ClaimStrings.
func NewClaimStrings(val []string, asString bool) ClaimStrings {
	return ClaimStrings{
		Value:    val,
		AsString: asString,
	}
}

// NewClaimSingleString constructs a new ClaimStrings.
func NewClaimSingleString(val string) ClaimStrings {
	return NewClaimStrings([]string{val}, true)
}

// NewClaimStringArray constructs a new ClaimStrings.
func NewClaimStringArray(val []string) ClaimStrings {
	return NewClaimStrings(val, false)
}

func (s *ClaimStrings) UnmarshalJSON(data []byte) (err error) {
	var value any

	if err = json.Unmarshal(data, &value); err != nil {
		return err
	}

	var aud []string
	var asString bool

	switch v := value.(type) {
	case string:
		aud = append(aud, v)
		asString = true
	case []string:
		aud = v
		asString = false
	case []any:
		for _, vv := range v {
			vs, ok := vv.(string)
			if !ok {
				return ErrJWTInvalidType
			}
			aud = append(aud, vs)
		}
		asString = false
	case nil:
		return nil
	default:
		return ErrJWTInvalidType
	}

	s.Value = aud
	s.AsString = asString

	return
}

func (s ClaimStrings) MarshalJSON() (b []byte, err error) {
	if len(s.Value) == 1 && s.AsString {
		return json.Marshal(s.Value[0])
	}

	return json.Marshal(s.Value)
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
func (m MapClaims) GetAudience() (ClaimStrings, error) {
	return m.parseClaimsString("aud")
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

// GetClaimsString implements the Claims interface.
func (m MapClaims) GetClaimsString(name string) (ClaimStrings, error) {
	return m.parseClaimsString(name)
}

// GetString implements the Claims interface.
func (m MapClaims) GetString(name string) (string, error) {
	return m.parseString(name)
}

// parseNumericDate tries to parse a key in the map claims type as a number date.
func (m MapClaims) parseNumericDate(key string) (*NumericDate, error) {
	v, ok := m[key]
	if !ok {
		return nil, NewError(fmt.Sprintf("%s is not exists", key), ErrJWTInvalidType)
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

	return nil, NewError(fmt.Sprintf("%s is invalid", key), ErrJWTInvalidType)
}

// parseClaimsString tries to parse a key in the map claims type as a
// [ClaimsStrings] type, which can either be a string or an array of string.
func (m MapClaims) parseClaimsString(key string) (ClaimStrings, error) {
	var cs []string
	var asString bool

	switch v := m[key].(type) {
	case string:
		cs = append(cs, v)
		asString = true
	case []string:
		cs = v
		asString = false
	case []any:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return ClaimStrings{}, NewError(fmt.Sprintf("%s is invalid", key), ErrJWTInvalidType)
			}

			cs = append(cs, vs)
		}

		asString = false
	}

	return ClaimStrings{
		Value:    cs,
		AsString: asString,
	}, nil
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
		return "", NewError(fmt.Sprintf("%s is invalid", key), ErrJWTInvalidType)
	}

	return iss, nil
}
