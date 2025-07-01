package jwt

// This class makes easier the token creation process
type Builder[S any, V any] struct {
	headers map[string]any
	claims  map[string]any

	signer  ISigner[S, V]
	encoder IEncoder
}

func NewBuilder[S any, V any](signer ISigner[S, V], encoder IEncoder) *Builder[S, V] {
	return &Builder[S, V]{
		headers: map[string]any{},
		claims:  map[string]any{},
		signer:  signer,
		encoder: encoder,
	}
}

// Configures a header item
func (b *Builder[S, V]) WithHeader(name string, value any) *Builder[S, V] {
	b.headers[name] = value
	return b
}

// Configures a claim item
func (b *Builder[S, V]) WithClaim(name string, value any) *Builder[S, V] {
	b.claims[name] = value
	return b
}

// Configures the header type
func (b *Builder[S, V]) HeaderType(value any) *Builder[S, V] {
	b.headers[RegisteredHeadersType] = value
	return b
}

// Configures the header algorithm
func (b *Builder[S, V]) HeaderAlgo(value any) *Builder[S, V] {
	b.headers[RegisteredHeadersAlgorithm] = value
	return b
}

// Configures the audience
func (b *Builder[S, V]) PermittedFor(audiences ClaimStrings) *Builder[S, V] {
	b.claims[RegisteredClaimsAudience] = audiences
	return b
}

// Configures the expiration time, expirTime
func (b *Builder[S, V]) ExpiresAt(expiration *NumericDate) *Builder[S, V] {
	b.claims[RegisteredClaimsExpirationTime] = expiration
	return b
}

// Configures the token id JwtId
func (b *Builder[S, V]) IdentifiedBy(id string) *Builder[S, V] {
	b.claims[RegisteredClaimsID] = id
	return b
}

// Configures the time that the token was issued
func (b *Builder[S, V]) IssuedAt(issuedAt *NumericDate) *Builder[S, V] {
	b.claims[RegisteredClaimsIssuedAt] = issuedAt
	return b
}

// Configures the issuer
func (b *Builder[S, V]) IssuedBy(issuer string) *Builder[S, V] {
	b.claims[RegisteredClaimsIssuer] = issuer
	return b
}

// Configures the time before which the token cannot be accepted
func (b *Builder[S, V]) CanOnlyBeUsedAfter(notBefore *NumericDate) *Builder[S, V] {
	b.claims[RegisteredClaimsNotBefore] = notBefore
	return b
}

// Configures the subject
func (b *Builder[S, V]) RelatedTo(subject string) *Builder[S, V] {
	b.claims[RegisteredClaimsSubject] = subject
	return b
}

// Returns the resultant token
func (b *Builder[S, V]) GetToken(key S) (*Token, error) {
	t := NewToken(b.encoder)
	t.SetHeader(b.headers)
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
