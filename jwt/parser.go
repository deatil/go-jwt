package jwt

import (
	"fmt"
)

// jwt ParserOption for Parse function
type ParserOption struct {
	// jwt encoder
	Encoder IEncoder

	// jwt valid methods
	ValidMethods []string
}

// default ParserOption
var JWTParserOption = ParserOption{
	Encoder: JWTEncoder,
}

// Parse parses the signature and returns the parsed token.
func Parse[V any](tokenString string, keyFunc func(t *Token) (key V, err error), opt ...ParserOption) (*Token, error) {
	var parserOpt ParserOption
	if len(opt) > 0 {
		parserOpt = opt[0]
	} else {
		parserOpt = ParserOption{
			Encoder: JWTEncoder,
		}
	}

	// if not set encoder, return error
	if parserOpt.Encoder == nil {
		return nil, ErrJWTEncoderInvalid
	}

	t := NewToken(parserOpt.Encoder)
	t.Parse(tokenString)

	if t.GetPartCount() < 2 {
		return nil, ErrJWTTokenInvalid
	}

	key, err := keyFunc(t)
	if err != nil {
		return nil, err
	}

	header, err := t.GetHeader()
	if err != nil {
		return nil, err
	}

	// if token type not empty and not equal JWT, return error
	if len(header.Typ) > 0 && header.Typ != "JWT" {
		return nil, ErrJWTTypeInvalid
	}

	// Verify signing method is in the required set
	if parserOpt.ValidMethods != nil {
		var signingMethodValid = false
		var alg = header.Alg
		for _, m := range parserOpt.ValidMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}

		if !signingMethodValid {
			return nil, NewError(fmt.Sprintf("signing method %v is invalid", alg), ErrJWTTokenSignatureInvalid)
		}
	}

	signingMethod := GetSigningMethod(header.Alg)
	if signingMethod == nil {
		return nil, ErrJWTMethodExists
	}

	signer, ok := signingMethod.(IVerifying[V])
	if !ok {
		return nil, ErrJWTMethodInvalid
	}

	signature := t.GetSignature()
	signingString := t.GetMsg()

	// check signature
	verifyStatus, _ := signer.Verify([]byte(signingString), signature, key)
	if !verifyStatus {
		return nil, ErrJWTVerifyFail
	}

	return t, nil
}
