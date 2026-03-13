package codebird

import "testing"

func TestParseAuthContext(t *testing.T) {
	claims := map[string]any{
		"sub":             "user_1",
		"email":           "demo@example.com",
		"organization_id": "org_1",
		"organizations":   []any{"org_1", "org_2"},
		"organization_roles": map[string]any{
			"org_1": []any{"admin"},
		},
		"organization_is_admin": true,
	}

	ctx, err := ParseAuthContext(claims)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if ctx.Subject != "user_1" {
		t.Fatalf("expected subject user_1, got %s", ctx.Subject)
	}

	if ctx.OrganizationID != "org_1" {
		t.Fatalf("expected organization id org_1, got %s", ctx.OrganizationID)
	}

	if !ctx.OrganizationIsAdmin {
		t.Fatalf("expected organization admin to be true")
	}
}

func TestParseAuthContext_SupportsOrganizationRoleArrayFormat(t *testing.T) {
	claims := map[string]any{
		"organization_roles": []any{
			"org_1:admin",
			"org_1:editor",
			"org_2:viewer",
		},
	}

	ctx, err := ParseAuthContext(claims)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(ctx.OrganizationRoles["org_1"]) != 2 {
		t.Fatalf("expected org_1 to have 2 roles, got %v", ctx.OrganizationRoles["org_1"])
	}

	if ctx.OrganizationRoles["org_1"][0] != "admin" || ctx.OrganizationRoles["org_1"][1] != "editor" {
		t.Fatalf("expected org_1 roles [admin editor], got %v", ctx.OrganizationRoles["org_1"])
	}

	if len(ctx.OrganizationRoles["org_2"]) != 1 || ctx.OrganizationRoles["org_2"][0] != "viewer" {
		t.Fatalf("expected org_2 roles [viewer], got %v", ctx.OrganizationRoles["org_2"])
	}
}
