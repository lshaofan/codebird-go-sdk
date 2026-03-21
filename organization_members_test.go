package codebird

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestM2MClient(t *testing.T, handler http.HandlerFunc) *M2MClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := NewM2MClient(M2MConfig{
		Endpoint:       server.URL,
		ClientID:       "client_1",
		ClientSecret:   "secret_1",
		Resource:       "urn:codebird:management-api:tenant_1",
		OrganizationID: "org_1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	return client
}

func TestListOrganizationMembers(t *testing.T) {
	var authHeader string
	var requestPath string
	var requestQuery string
	var tokenRequests int
	var tokenRequestBody string

	client := newTestM2MClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			tokenRequests++
			body, _ := io.ReadAll(r.Body)
			tokenRequestBody = string(body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "m2m_token_1",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v1/m2m/organizations/org_1/members":
			authHeader = r.Header.Get("Authorization")
			requestPath = r.URL.Path
			requestQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    0,
				"message": "success",
				"result": map[string]any{
					"total": 1,
					"data": []map[string]any{
						{
							"id":            "user_1",
							"username":      "demo",
							"primary_phone": "13800000000",
							"name":          "Demo User",
							"is_admin":      false,
							"joined_at":     "2026-03-13T12:00:00Z",
							"created_at":    "2026-03-13T12:00:00Z",
						},
					},
					"page":      1,
					"page_size": 20,
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	result, err := client.ListOrganizationMembers(context.Background(), "org_1", ListOrganizationMembersInput{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if tokenRequests != 1 {
		t.Fatalf("expected one token request, got %d", tokenRequests)
	}
	if !strings.Contains(tokenRequestBody, "organization_id=org_1") {
		t.Fatalf("expected organization_id in token request, got %q", tokenRequestBody)
	}
	if !strings.Contains(tokenRequestBody, "resource=urn%3Acodebird%3Amanagement-api%3Atenant_1") {
		t.Fatalf("expected resource in token request, got %q", tokenRequestBody)
	}

	if authHeader != "Bearer m2m_token_1" {
		t.Fatalf("expected bearer token, got %q", authHeader)
	}

	if requestPath != "/api/v1/m2m/organizations/org_1/members" {
		t.Fatalf("expected members path, got %q", requestPath)
	}

	if !strings.Contains(requestQuery, "page=1") || !strings.Contains(requestQuery, "page_size=20") {
		t.Fatalf("expected pagination query, got %q", requestQuery)
	}

	if result.Total != 1 || len(result.Data) != 1 {
		t.Fatalf("expected single member result, got %+v", result)
	}

	if result.Data[0].ID != "user_1" {
		t.Fatalf("expected user_1, got %+v", result.Data[0])
	}
}

func TestAddOrganizationMember(t *testing.T) {
	var authHeader string
	var requestBody string
	var requestMethod string

	client := newTestM2MClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "m2m_token_1",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v1/m2m/organizations/org_1/members":
			authHeader = r.Header.Get("Authorization")
			requestMethod = r.Method
			body, _ := io.ReadAll(r.Body)
			requestBody = string(body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    0,
				"message": "success",
				"result": map[string]any{
					"id":            "user_2",
					"username":      "new-user",
					"primary_phone": "13800000001",
					"primary_email": "new@example.com",
					"name":          "New User",
					"is_admin":      false,
					"joined_at":     "2026-03-13T12:01:00Z",
					"created_at":    "2026-03-13T12:01:00Z",
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	result, err := client.AddOrganizationMember(context.Background(), "org_1", AddOrganizationMemberInput{
		Phone: "13800000001",
		Name:  "New User",
		Email: "new@example.com",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if authHeader != "Bearer m2m_token_1" {
		t.Fatalf("expected bearer token, got %q", authHeader)
	}
	if requestMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", requestMethod)
	}
	if !strings.Contains(requestBody, `"phone":"13800000001"`) {
		t.Fatalf("expected phone in body, got %q", requestBody)
	}
	if result.ID != "user_2" {
		t.Fatalf("expected user_2, got %+v", result)
	}
}

func TestRemoveOrganizationMember(t *testing.T) {
	var requestMethod string
	var requestPath string

	client := newTestM2MClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "m2m_token_1",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v1/m2m/organizations/org_1/members/user_1":
			requestMethod = r.Method
			requestPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    0,
				"message": "success",
				"result":  nil,
			})
		default:
			http.NotFound(w, r)
		}
	})

	if err := client.RemoveOrganizationMember(context.Background(), "org_1", "user_1"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if requestMethod != http.MethodDelete {
		t.Fatalf("expected DELETE, got %s", requestMethod)
	}
	if requestPath != "/api/v1/m2m/organizations/org_1/members/user_1" {
		t.Fatalf("expected delete path, got %q", requestPath)
	}
}

func TestGetOrganizationMemberRoles(t *testing.T) {
	var requestPath string

	client := newTestM2MClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "m2m_token_1",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v1/m2m/organizations/org_1/members/user_1/roles":
			requestPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    0,
				"message": "success",
				"result": []map[string]any{
					{
						"id":          "role_1",
						"name":        "member-manager",
						"description": "Can manage organization members",
						"type":        "User",
						"created_at":  "2026-03-01T08:00:00Z",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	roles, err := client.GetOrganizationMemberRoles(context.Background(), "org_1", "user_1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if requestPath != "/api/v1/m2m/organizations/org_1/members/user_1/roles" {
		t.Fatalf("expected roles path, got %q", requestPath)
	}
	if len(roles) != 1 || roles[0].ID != "role_1" {
		t.Fatalf("expected role_1, got %+v", roles)
	}
}

func TestUpdateOrganizationMemberRoles(t *testing.T) {
	var requestMethod string
	var requestBody string

	client := newTestM2MClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oidc/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "m2m_token_1",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v1/m2m/organizations/org_1/members/user_1/roles":
			requestMethod = r.Method
			body, _ := io.ReadAll(r.Body)
			requestBody = string(body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    0,
				"message": "success",
				"result":  nil,
			})
		default:
			http.NotFound(w, r)
		}
	})

	err := client.UpdateOrganizationMemberRoles(context.Background(), "org_1", "user_1", UpdateOrganizationMemberRolesInput{
		RoleIDs: []string{"role_1", "role_2"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if requestMethod != http.MethodPut {
		t.Fatalf("expected PUT, got %s", requestMethod)
	}
	if !strings.Contains(requestBody, `"role_ids":["role_1","role_2"]`) {
		t.Fatalf("expected role_ids in body, got %q", requestBody)
	}
}
