package jwt

// Defines "JSON Web Token Headers" struct
type registeredStdHeaders struct {
	Type        string
	Algorithm   string
	KeyID       string
	ContentType string
	Encryption  string
}

// Defines "JSON Web Token Claims" struct
type registeredStdClaims struct {
	Audience       string
	ExpirationTime string
	ID             string
	IssuedAt       string
	Issuer         string
	NotBefore      string
	Subject        string
}

// Defines the list of headers that are registered in the IANA "JSON Web Token Headers" registry
var RegisteredStdHeaders = registeredStdHeaders{
	Type:        "typ",
	Algorithm:   "alg",
	KeyID:       "kid",
	ContentType: "cty",
	Encryption:  "enc",
}

// Defines the list of claims that are registered in the IANA "JSON Web Token Claims" registry
var RegisteredStdClaims = registeredStdClaims{
	Audience:       "aud",
	ExpirationTime: "exp",
	ID:             "jti",
	IssuedAt:       "iat",
	Issuer:         "iss",
	NotBefore:      "nbf",
	Subject:        "sub",
}
