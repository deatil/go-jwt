package encoder

type Options func(*JoseEncoder)

// WithJSONNumber is an option to configure the underlying JSON parser with
// UseNumber.
func WithJSONNumber() Options {
	return func(e *JoseEncoder) {
		e.useJSONNumber = true
	}
}

// WithStrictDecoding will switch the codec used for decoding JWTs into strict
// mode. In this mode, the decoder requires that trailing padding bits are zero,
// as described in RFC 4648 section 3.5.
func WithStrictDecoding() Options {
	return func(e *JoseEncoder) {
		e.decodeStrict = true
	}
}

// WithPaddingAllowed will enable the codec used for decoding JWTs to allow
// padding.
func WithPaddingAllowed() Options {
	return func(e *JoseEncoder) {
		e.decodePaddingAllowed = true
	}
}
