package codebird

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewVerifier_RequiresIssuerAndAudience(t *testing.T) {
	_, err := NewVerifier(Config{})
	if err == nil {
		t.Fatalf("expected error for missing issuer and audience")
	}
}

func TestVerifyAccessToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	keyID := "test-key"
	audience := "https://api.example.com"

	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   discoveryServer.URL,
				"jwks_uri": discoveryServer.URL + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"kty": "EC",
						"crv": "P-256",
						"kid": keyID,
						"alg": "ES256",
						"use": "sig",
						"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
						"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer discoveryServer.Close()

	issuer := discoveryServer.URL

	verifier, err := NewVerifier(Config{
		Issuer:   issuer,
		Audience: audience,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	validToken := signTestToken(t, privateKey, keyID, issuer, audience)

	authContext, err := verifier.VerifyAccessToken(context.Background(), validToken)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if authContext.Subject != "user_1" {
		t.Fatalf("expected subject user_1, got %s", authContext.Subject)
	}

	invalidAudienceToken := signTestToken(t, privateKey, keyID, issuer, "https://wrong-api.example.com")

	_, err = verifier.VerifyAccessToken(context.Background(), invalidAudienceToken)
	if err == nil || !IsInvalidAudience(err) {
		t.Fatalf("expected invalid audience error, got %v", err)
	}

	invalidIssuerToken := signTestToken(t, privateKey, keyID, "http://wrong-issuer.example.com", audience)

	_, err = verifier.VerifyAccessToken(context.Background(), invalidIssuerToken)
	if err == nil || !IsInvalidIssuer(err) {
		t.Fatalf("expected invalid issuer error, got %v", err)
	}
}

func TestVerifyAccessToken_UsesJWKSCache(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	keyID := "cached-key"
	audience := "https://api.example.com"
	var jwksRequests int

	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   discoveryServer.URL,
				"jwks_uri": discoveryServer.URL + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			jwksRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"kty": "EC",
						"crv": "P-256",
						"kid": keyID,
						"alg": "ES256",
						"use": "sig",
						"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
						"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer discoveryServer.Close()

	verifier, err := NewVerifier(Config{
		Issuer:   discoveryServer.URL,
		Audience: audience,
		JWKSTTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token := signTestToken(t, privateKey, keyID, discoveryServer.URL, audience)

	if _, err := verifier.VerifyAccessToken(context.Background(), token); err != nil {
		t.Fatalf("expected first verify to pass, got %v", err)
	}
	if _, err := verifier.VerifyAccessToken(context.Background(), token); err != nil {
		t.Fatalf("expected second verify to pass, got %v", err)
	}

	if jwksRequests != 1 {
		t.Fatalf("expected jwks to be fetched once, got %d", jwksRequests)
	}
}

func TestVerifyAccessToken_ReturnsTypedErrorsForExpiredAndNotActiveTokens(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	keyID := "error-key"
	audience := "https://api.example.com"

	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   discoveryServer.URL,
				"jwks_uri": discoveryServer.URL + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"kty": "EC",
						"crv": "P-256",
						"kid": keyID,
						"alg": "ES256",
						"use": "sig",
						"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
						"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer discoveryServer.Close()

	verifier, err := NewVerifier(Config{
		Issuer:   discoveryServer.URL,
		Audience: audience,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expiredToken := signCustomTestToken(t, privateKey, keyID, discoveryServer.URL, audience, time.Now().Add(-5*time.Minute), time.Now().Add(-10*time.Minute))
	_, err = verifier.VerifyAccessToken(context.Background(), expiredToken)
	if err == nil || !IsTokenExpired(err) {
		t.Fatalf("expected token expired error, got %v", err)
	}

	notActiveToken := signCustomTestToken(t, privateKey, keyID, discoveryServer.URL, audience, time.Now().Add(5*time.Minute), time.Now().Add(5*time.Minute))
	_, err = verifier.VerifyAccessToken(context.Background(), notActiveToken)
	if err == nil || !IsTokenNotActive(err) {
		t.Fatalf("expected token not active error, got %v", err)
	}
}

func TestVerifyAccessToken_ReturnsJWKSFetchError(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	verifier, err := NewVerifier(Config{
		Issuer:   "http://127.0.0.1:1",
		Audience: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token := signTestToken(t, privateKey, "unreachable-key", "http://127.0.0.1:1", "https://api.example.com")

	_, err = verifier.VerifyAccessToken(context.Background(), token)
	if err == nil || !IsJWKSFetchFailed(err) {
		t.Fatalf("expected jwks fetch failure, got %v", err)
	}
}

func signTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, keyID, issuer, audience string) string {
	t.Helper()

	now := time.Now()
	return signCustomTestToken(t, privateKey, keyID, issuer, audience, now.Add(5*time.Minute), now.Add(-1*time.Minute))
}

func signCustomTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, keyID, issuer, audience string, exp, nbf time.Time) string {
	t.Helper()

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":                   issuer,
		"sub":                   "user_1",
		"aud":                   audience,
		"exp":                   exp.Unix(),
		"nbf":                   nbf.Unix(),
		"iat":                   now.Unix(),
		"email":                 "demo@example.com",
		"organization_id":       "org_1",
		"organizations":         []string{"org_1", "org_2"},
		"organization_roles":    map[string][]string{"org_1": {"admin"}},
		"organization_is_admin": true,
	})
	token.Header["kid"] = keyID

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return signed
}
