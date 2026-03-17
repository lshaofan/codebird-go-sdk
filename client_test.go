package codebird

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_RequiresIssuer(t *testing.T) {
	_, err := NewClient(Config{})
	if err == nil {
		t.Fatalf("expected error when issuer is missing")
	}
}

func TestGetSessionContext(t *testing.T) {
	var gotAuthorization string
	var gotOrganizationID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotOrganizationID = r.URL.Query().Get("organization_id")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    0,
			"message": "success",
			"result": map[string]any{
				"tenant": map[string]any{
					"id":   "default",
					"slug": "default",
					"name": "默认租户",
				},
				"user": map[string]any{
					"id":           "user_1",
					"username":     "demo",
					"name":         "Demo User",
					"email":        "demo@example.com",
					"phone_number": "13800000000",
					"avatar":       "https://example.com/avatar.png",
					"updated_at":   int64(1771311069),
				},
				"application": map[string]any{
					"id":        "app_1",
					"name":      "Demo App",
					"type":      "SPA",
					"tenant_id": "default",
				},
				"organization": map[string]any{
					"id":        "org_1",
					"name":      "Org 1",
					"logo_url":  "https://example.com/logo.png",
					"is_member": true,
					"is_admin":  true,
					"roles":     []string{"admin"},
				},
				"organizations": []map[string]any{
					{
						"id":       "org_1",
						"name":     "Org 1",
						"logo_url": "https://example.com/logo.png",
					},
				},
				"session": map[string]any{
					"subject":                 "user_1",
					"client_id":               "app_1",
					"scopes":                  []string{"openid", "profile"},
					"current_organization_id": "org_1",
				},
			},
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Issuer: server.URL,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	result, err := client.GetSessionContext(context.Background(), "access_token_1", &GetSessionContextOptions{
		OrganizationID: "org_1",
	})
	if err != nil {
		t.Fatalf("get session context: %v", err)
	}

	if gotAuthorization != "Bearer access_token_1" {
		t.Fatalf("expected bearer token to be forwarded, got %q", gotAuthorization)
	}
	if gotOrganizationID != "org_1" {
		t.Fatalf("expected organization_id=org_1, got %q", gotOrganizationID)
	}
	if result.User.ID != "user_1" {
		t.Fatalf("expected user id user_1, got %q", result.User.ID)
	}
	if result.Tenant == nil || result.Tenant.Slug != "default" {
		t.Fatalf("expected tenant slug default, got %+v", result.Tenant)
	}
	if result.Application == nil || result.Application.ID != "app_1" {
		t.Fatalf("expected application app_1, got %+v", result.Application)
	}
	if result.Organization == nil || result.Organization.ID != "org_1" {
		t.Fatalf("expected organization org_1, got %+v", result.Organization)
	}
	if result.Session.ClientID == nil || *result.Session.ClientID != "app_1" {
		t.Fatalf("expected session client id app_1, got %+v", result.Session.ClientID)
	}
}

func TestGetSessionContext_ReturnsErrorOnNonOKResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    20511,
			"message": "当前组织不存在或你已无权访问",
		})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Issuer: server.URL,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.GetSessionContext(context.Background(), "access_token_1", &GetSessionContextOptions{
		OrganizationID: "org_1",
	})
	if err == nil {
		t.Fatal("expected non-OK response to return error")
	}
}

func TestBuildTenantAuthURLs(t *testing.T) {
	client, err := NewClient(Config{
		Issuer: "https://auth.example.com",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	signInURL, err := client.BuildTenantSignInURL("tenant-demo")
	if err != nil {
		t.Fatalf("build sign-in url: %v", err)
	}
	if signInURL != "https://auth.example.com/t/tenant-demo/sign-in" {
		t.Fatalf("unexpected sign-in url: %q", signInURL)
	}

	registerURL, err := client.BuildTenantRegisterURL("tenant-demo")
	if err != nil {
		t.Fatalf("build register url: %v", err)
	}
	if registerURL != "https://auth.example.com/t/tenant-demo/register" {
		t.Fatalf("unexpected register url: %q", registerURL)
	}

	forgotPasswordURL, err := client.BuildTenantForgotPasswordURL("tenant-demo")
	if err != nil {
		t.Fatalf("build forgot-password url: %v", err)
	}
	if forgotPasswordURL != "https://auth.example.com/t/tenant-demo/forgot-password" {
		t.Fatalf("unexpected forgot-password url: %q", forgotPasswordURL)
	}
}

func TestBuildTenantAuthURLs_RequireTenantSlug(t *testing.T) {
	client, err := NewClient(Config{
		Issuer: "https://auth.example.com",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.BuildTenantSignInURL("   "); err == nil {
		t.Fatal("expected empty tenant slug to return error")
	}
}
