package codebird

import "testing"

func TestNewM2MClient_RequiresConfig(t *testing.T) {
	t.Run("requires endpoint", func(t *testing.T) {
		_, err := NewM2MClient(M2MConfig{})
		if err == nil {
			t.Fatalf("expected error for missing endpoint")
		}
	})

	t.Run("requires client id", func(t *testing.T) {
		_, err := NewM2MClient(M2MConfig{
			Endpoint: "https://auth.example.com",
		})
		if err == nil {
			t.Fatalf("expected error for missing client id")
		}
	})

	t.Run("requires client secret", func(t *testing.T) {
		_, err := NewM2MClient(M2MConfig{
			Endpoint: "https://auth.example.com",
			ClientID: "client_1",
		})
		if err == nil {
			t.Fatalf("expected error for missing client secret")
		}
	})

	t.Run("allows empty resource for organization scope token", func(t *testing.T) {
		_, err := NewM2MClient(M2MConfig{
			Endpoint:       "https://auth.example.com",
			ClientID:       "client_1",
			ClientSecret:   "secret_1",
			OrganizationID: "org_1",
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}
