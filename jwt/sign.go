package jwt

import (
	"io"
)

type ISigned[S any] interface {
	Sign(random io.Reader, claims any, signKey S) (string, error)
}

func Sign[S any](SigningMethod ISigned[S], random io.Reader, claims any, key S) (string, error) {
	return SigningMethod.Sign(random, claims, key)
}
