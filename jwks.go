package codebird

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

type jwksCache struct {
	mu               sync.Mutex
	httpClient       *http.Client
	jwksTTL          time.Duration
	discoveryURL     string
	jwksURI          string
	lastRefreshed    time.Time
	verificationKeys map[string]any
}

func newJWKSCache(discoveryURL string, ttl time.Duration) *jwksCache {
	return &jwksCache{
		httpClient:       http.DefaultClient,
		jwksTTL:          ttl,
		discoveryURL:     discoveryURL,
		verificationKeys: map[string]any{},
	}
}

func (c *jwksCache) Key(kid string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.refreshIfNeeded(); err != nil {
		return nil, err
	}

	key, ok := c.verificationKeys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: signing key %s not found", ErrJWKSFetchFailed, kid)
	}

	return key, nil
}

func (c *jwksCache) refreshIfNeeded() error {
	if c.jwksURI != "" && time.Since(c.lastRefreshed) < c.jwksTTL && len(c.verificationKeys) > 0 {
		return nil
	}

	if err := c.loadDiscovery(); err != nil {
		return err
	}

	return c.loadJWKS()
}

func (c *jwksCache) loadDiscovery() error {
	response, err := c.httpClient.Get(c.discoveryURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: discovery returned %d", ErrJWKSFetchFailed, response.StatusCode)
	}

	var document discoveryDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	if document.Issuer == "" || document.JWKSURI == "" {
		return fmt.Errorf("%w: invalid discovery document", ErrJWKSFetchFailed)
	}

	c.jwksURI = document.JWKSURI
	return nil
}

func (c *jwksCache) loadJWKS() error {
	response, err := c.httpClient.Get(c.jwksURI)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: jwks returned %d", ErrJWKSFetchFailed, response.StatusCode)
	}

	var document jwksDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetchFailed, err)
	}
	if len(document.Keys) == 0 {
		return fmt.Errorf("%w: empty jwks", ErrJWKSFetchFailed)
	}

	keys := map[string]any{}
	for _, key := range document.Keys {
		publicKey, err := parseJWK(key)
		if err != nil {
			return err
		}
		keys[key.KeyID] = publicKey
	}

	c.verificationKeys = keys
	c.lastRefreshed = time.Now()
	return nil
}

func parseJWK(key jwkKey) (any, error) {
	if key.KeyType != "EC" || key.Curve != "P-256" {
		return nil, fmt.Errorf("%w: unsupported jwk type", ErrJWKSFetchFailed)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid jwk x", ErrJWKSFetchFailed)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid jwk y", ErrJWKSFetchFailed)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func isJWKSFetchError(err error) bool {
	return errors.Is(err, ErrJWKSFetchFailed)
}
