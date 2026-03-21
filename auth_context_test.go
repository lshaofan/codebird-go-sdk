package codebird

import "testing"

func TestAuthContextHelpers(t *testing.T) {
	ctx := AuthContext{
		OrganizationID:    "org_1",
		OrganizationIDs:   []string{"org_1", "org_2"},
		OrganizationRoles: map[string][]string{"org_1": {"admin", "editor"}},
		Audience:          []string{"https://api.example.com"},
	}

	if !ctx.HasAudience("https://api.example.com") {
		t.Fatal("expected audience helper to match existing audience")
	}

	if !ctx.HasOrganization("org_2") {
		t.Fatal("expected organization helper to match organization ids")
	}

	if !ctx.HasOrganizationRole("org_1", "admin") {
		t.Fatal("expected organization role helper to match admin role")
	}

	roles := ctx.RolesForOrganization("org_1")
	if len(roles) != 2 || roles[0] != "admin" || roles[1] != "editor" {
		t.Fatalf("expected roles [admin editor], got %v", roles)
	}

	roles[0] = "changed"
	if ctx.OrganizationRoles["org_1"][0] != "admin" {
		t.Fatalf("expected helper to return a copy, got %v", ctx.OrganizationRoles["org_1"])
	}
}
