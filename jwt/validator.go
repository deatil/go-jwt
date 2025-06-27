package jwt

type Validator struct {
	claims map[string]any
	leeway int64
}

func NewValidator(token *Token) (*Validator, error) {
	claims, err := token.GetClaims()
	if err != nil {
		return nil, err
	}

	return &Validator{
		claims: claims,
		leeway: 0,
	}, nil
}

func (v *Validator) WithLeeway(leeway int64) *Validator {
	v.leeway = leeway
	return v
}

func (v *Validator) IsPermittedFor(audience string) bool {
	if val, ok := v.claims["aud"]; ok {
		if vv, ok2 := val.(string); ok2 && vv == audience {
			return true
		}
	}

	return false
}

func (v *Validator) IsIdentifiedBy(id string) bool {
	if val, ok := v.claims["jti"]; ok {
		if vv, ok2 := val.(string); ok2 && vv == id {
			return true
		}
	}

	return false
}

func (v *Validator) IsRelatedTo(subject string) bool {
	if val, ok := v.claims["sub"]; ok {
		if vv, ok2 := val.(string); ok2 && vv == subject {
			return true
		}
	}

	return false
}

func (v *Validator) HasBeenIssuedBy(issuer string) bool {
	if val, ok := v.claims["iss"]; ok {
		if vv, ok2 := val.(string); ok2 && vv == issuer {
			return true
		}
	}

	return false
}

func (v *Validator) HasBeenIssuedBefore(now int64) bool {
	if val, ok := v.claims["iat"]; ok {
		if vv, ok2 := val.(float64); ok2 {
			if now+v.leeway > int64(vv) {
				return true
			}
		}

		return false
	}

	return true
}

func (v *Validator) IsMinimumTimeBefore(now int64) bool {
	if val, ok := v.claims["nbf"]; ok {
		if vv, ok2 := val.(float64); ok2 {
			if now+v.leeway > int64(vv) {
				return true
			}
		}

		return false
	}

	return true
}

func (v *Validator) IsExpired(now int64) bool {
	if val, ok := v.claims["exp"]; ok {
		if vv, ok2 := val.(float64); ok2 {
			if now-v.leeway < int64(vv) {
				return false
			}
		}

		return true
	}

	return false
}
