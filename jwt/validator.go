package jwt

// jwt token validator
type Validator struct {
	claims MapClaims
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

func (v *Validator) IsPermittedFor(audiences []string) bool {
	getAudiences, err := v.claims.GetAudience()
	if err != nil {
		return false
	}

	for _, val := range getAudiences.Value {
		for _, audience := range audiences {
			if val == audience {
				return true
			}	
		}
	}

	return false
}

func (v *Validator) IsIdentifiedBy(id string) bool {
	val, err := v.claims.GetString("jti")
	if err != nil {
		return false
	}

	if val == id {
		return true
	}

	return false
}

func (v *Validator) IsRelatedTo(subjects []string) bool {
	val, err := v.claims.GetSubject()
	if err != nil {
		return false
	}

	for _, subject := range subjects {
		if val == subject {
			return true
		}
	}

	return false
}

func (v *Validator) HasBeenIssuedBy(issuers []string) bool {
	val, err := v.claims.GetIssuer()
	if err != nil {
		return false
	}

	for _, issuer := range issuers {
		if val == issuer {
			return true
		}	
	}

	return false
}

func (v *Validator) HasBeenIssuedBefore(now int64) bool {
	if val, ok := v.claims["iat"]; ok {
		if vv, ok := val.(float64); ok {
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
		if vv, ok := val.(float64); ok {
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
		if vv, ok := val.(float64); ok {
			if now-v.leeway < int64(vv) {
				return false
			}
		}

		return true
	}

	return false
}
