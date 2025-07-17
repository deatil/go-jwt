package jwt

import (
	"sync"
)

var signingMethods = map[string]func() any{}
var signingMethodLock = new(sync.RWMutex)

// RegisterSigningMethod registers the "alg" name and a factory function for signing method.
func RegisterSigningMethod(alg string, f func() any) {
	signingMethodLock.Lock()
	defer signingMethodLock.Unlock()

	signingMethods[alg] = f
}

// GetSigningMethod retrieves a signing method from an "alg" string
func GetSigningMethod(alg string) (method any) {
	signingMethodLock.RLock()
	defer signingMethodLock.RUnlock()

	if methodFunc, ok := signingMethods[alg]; ok {
		method = methodFunc()
		return
	}

	return
}

// GetSigningMethodAlgs returns a list of registered "alg" names
func GetSigningMethodAlgs() (algs []string) {
	signingMethodLock.RLock()
	defer signingMethodLock.RUnlock()

	for alg := range signingMethods {
		algs = append(algs, alg)
	}

	return
}
