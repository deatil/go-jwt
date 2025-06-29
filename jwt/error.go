package jwt

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidType = errors.New("invalid type for claim")
)

// newError creates a new error message with a detailed error message.
func newError(message string, err error, more ...error) error {
	var format string
	var args []any
	if message != "" {
		format = "%w: %s"
		args = []any{err, message}
	} else {
		format = "%w"
		args = []any{err}
	}

	for _, e := range more {
		format += ": %w"
		args = append(args, e)
	}

	err = fmt.Errorf(format, args...)
	return err
}
