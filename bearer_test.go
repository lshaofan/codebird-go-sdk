package codebird

import "testing"

func TestParseBearerToken(t *testing.T) {
	token, err := ParseBearerToken("Bearer abc123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token != "abc123" {
		t.Fatalf("expected token abc123, got %s", token)
	}
}

func TestParseBearerToken_ReturnsTypedErrors(t *testing.T) {
	_, err := ParseBearerToken("")
	if !IsMissingAuthorizationHeader(err) {
		t.Fatalf("expected missing authorization header error, got %v", err)
	}

	_, err = ParseBearerToken("Basic abc123")
	if !IsInvalidAuthorizationHeader(err) {
		t.Fatalf("expected invalid authorization header error, got %v", err)
	}
}
