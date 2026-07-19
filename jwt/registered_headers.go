package jwt

// RegisteredHeaders are a structured version of the JWT Headers Set,
type RegisteredHeaders struct {
	// type
	Type        string `json:"typ,omitempty"`
	// algorithm
	Algorithm   string `json:"alg,omitempty"`
	// key id
	KeyID       string `json:"kid,omitempty"`
	// content type
	ContentType string `json:"cty,omitempty"`
}

func (h RegisteredHeaders) GetType() (string, error) {
	return h.Type, nil
}

func (h RegisteredHeaders) GetAlgorithm() (string, error) {
	return h.Algorithm, nil
}

func (h RegisteredHeaders) GetKeyID() (string, error) {
	return h.KeyID, nil
}

func (h RegisteredHeaders) GetContentType() (string, error) {
	return h.ContentType, nil
}

