package jwt

import "io"

type ISigned[S any] interface {
	WithRandom(random io.Reader)
	Sign(claims any, signKey S) (string, error)
}

func Sign[S any](SigningMethod ISigned[S], random io.Reader, claims any, key S) (string, error) {
	s := SigningMethod
	s.WithRandom(random)
	return SigningMethod.Sign(claims, key)
}
