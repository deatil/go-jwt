package jwt

// This class makes easier the token creation process
type Builder[S any] struct {
	headers map[string]any
	claims  map[string]any

	signer  ISigning[S]
	encoder IEncoder
}

func NewBuilder[S any](signer ISigning[S], encoder IEncoder) *Builder[S] {
	return &Builder[S]{
		headers: map[string]any{},
		claims:  map[string]any{},

		signer:  signer,
		encoder: encoder,
	}
}

// Configures a header item
func (b *Builder[S]) WithHeader(name string, value any) *Builder[S] {
	b.headers[name] = value
	return b
}

// Configures a claim item
func (b *Builder[S]) WithClaim(name string, value any) *Builder[S] {
	b.claims[name] = value
	return b
}

// Configures the header type
func (b *Builder[S]) HeaderType(value any) *Builder[S] {
	b.headers[RegisteredHeadersType] = value
	return b
}

// Configures the header algorithm
func (b *Builder[S]) HeaderAlgo(value any) *Builder[S] {
	b.headers[RegisteredHeadersAlgorithm] = value
	return b
}

// Configures the audience
func (b *Builder[S]) PermittedFor(audiences ClaimStrings) *Builder[S] {
	b.claims[RegisteredClaimsAudience] = audiences
	return b
}

// Configures the expiration time, expirTime
func (b *Builder[S]) ExpiresAt(expiration *NumericDate) *Builder[S] {
	b.claims[RegisteredClaimsExpirationTime] = expiration
	return b
}

// Configures the token id JwtId
func (b *Builder[S]) IdentifiedBy(id string) *Builder[S] {
	b.claims[RegisteredClaimsID] = id
	return b
}

// Configures the time that the token was issued
func (b *Builder[S]) IssuedAt(issuedAt *NumericDate) *Builder[S] {
	b.claims[RegisteredClaimsIssuedAt] = issuedAt
	return b
}

// Configures the issuer
func (b *Builder[S]) IssuedBy(issuer string) *Builder[S] {
	b.claims[RegisteredClaimsIssuer] = issuer
	return b
}

// Configures the time before which the token cannot be accepted
func (b *Builder[S]) CanOnlyBeUsedAfter(notBefore *NumericDate) *Builder[S] {
	b.claims[RegisteredClaimsNotBefore] = notBefore
	return b
}

// Configures the subject
func (b *Builder[S]) RelatedTo(subject string) *Builder[S] {
	b.claims[RegisteredClaimsSubject] = subject
	return b
}

// Returns the resultant token
func (b *Builder[S]) GetToken(key S) (*Token, error) {
	t := NewToken(b.encoder)

	headers := b.headers
	if _, ok := headers[RegisteredHeadersType]; !ok {
		headers[RegisteredHeadersType] = "JWT"
	}
	if _, ok := headers[RegisteredHeadersAlgorithm]; !ok {
		headers[RegisteredHeadersAlgorithm] = b.signer.Alg()
	}

	t.SetHeader(headers)
	t.SetClaims(b.claims)

	signingString, err := t.SigningString()
	if err != nil {
		return nil, err
	}

	signature, err := b.signer.Sign([]byte(signingString), key)
	if err != nil {
		return nil, err
	}

	t.WithSignature(signature)

	return t, nil
}
