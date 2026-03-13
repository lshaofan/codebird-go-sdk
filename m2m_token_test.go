package codebird

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestM2MClient_GetToken_UsesClientCredentials(t *testing.T) {
	var requestBody string
	var requestContentType string
	var requestMethod string
	var requestPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMethod = r.Method
		requestPath = r.URL.Path
		requestContentType = r.Header.Get("Content-Type")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		requestBody = string(body)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "m2m_token_1",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client, err := NewM2MClient(M2MConfig{
		Endpoint:     server.URL,
		ClientID:     "client_1",
		ClientSecret: "secret_1",
		Resource:     "urn:codebird:management-api:tenant_1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token, err := client.getToken(context.Background())
	if err != nil {
		t.Fatalf("expected token request to succeed, got %v", err)
	}

	if token != "m2m_token_1" {
		t.Fatalf("expected token m2m_token_1, got %q", token)
	}

	if requestMethod != http.MethodPost {
		t.Fatalf("expected POST request, got %s", requestMethod)
	}

	if requestPath != "/oidc/token" {
		t.Fatalf("expected /oidc/token, got %s", requestPath)
	}

	if !strings.Contains(requestContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("expected form content type, got %q", requestContentType)
	}

	if !strings.Contains(requestBody, "grant_type=client_credentials") {
		t.Fatalf("expected client_credentials grant, got %q", requestBody)
	}

	if !strings.Contains(requestBody, "client_id=client_1") {
		t.Fatalf("expected client_id in body, got %q", requestBody)
	}

	if !strings.Contains(requestBody, "client_secret=secret_1") {
		t.Fatalf("expected client_secret in body, got %q", requestBody)
	}

	if !strings.Contains(requestBody, "resource=urn%3Acodebird%3Amanagement-api%3Atenant_1") {
		t.Fatalf("expected resource in body, got %q", requestBody)
	}
}

func TestM2MClient_GetToken_CachesTokenUntilExpiry(t *testing.T) {
	var tokenRequests int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "m2m_token_1",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client, err := NewM2MClient(M2MConfig{
		Endpoint:     server.URL,
		ClientID:     "client_1",
		ClientSecret: "secret_1",
		Resource:     "urn:codebird:management-api:tenant_1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	first, err := client.getToken(context.Background())
	if err != nil {
		t.Fatalf("expected first token request to succeed, got %v", err)
	}
	second, err := client.getToken(context.Background())
	if err != nil {
		t.Fatalf("expected second token request to succeed, got %v", err)
	}

	if first != "m2m_token_1" || second != "m2m_token_1" {
		t.Fatalf("expected cached token reuse, got %q and %q", first, second)
	}

	if tokenRequests != 1 {
		t.Fatalf("expected token endpoint to be called once, got %d", tokenRequests)
	}
}

func TestM2MClient_GetToken_RefreshesExpiredToken(t *testing.T) {
	var tokenRequests int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "m2m_token_2",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client, err := NewM2MClient(M2MConfig{
		Endpoint:     server.URL,
		ClientID:     "client_1",
		ClientSecret: "secret_1",
		Resource:     "urn:codebird:management-api:tenant_1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	client.token = &m2mToken{
		AccessToken: "expired_token",
		ExpiresAt:   time.Now().Add(-time.Minute),
	}

	token, err := client.getToken(context.Background())
	if err != nil {
		t.Fatalf("expected token refresh to succeed, got %v", err)
	}

	if token != "m2m_token_2" {
		t.Fatalf("expected refreshed token m2m_token_2, got %q", token)
	}

	if tokenRequests != 1 {
		t.Fatalf("expected token endpoint to be called once, got %d", tokenRequests)
	}
}
