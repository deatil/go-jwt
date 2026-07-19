package jwt

type ISigned[S any] interface {
	Sign(claims any, signKey S) (string, error)
}

func Sign[S any](SigningMethod ISigned[S], claims any, key S) (string, error) {
	return SigningMethod.Sign(claims, key)
}
