package codebird

import "time"

type AuthContext struct {
	Subject             string
	Username            string
	Name                string
	Email               string
	PhoneNumber         string
	OrganizationID      string
	OrganizationIDs     []string
	OrganizationRoles   map[string][]string
	OrganizationIsAdmin bool
	Issuer              string
	Audience            []string
	ExpiresAt           time.Time
	NotBefore           *time.Time
	RawClaims           map[string]any
}

func (c AuthContext) HasAudience(audience string) bool {
	for _, item := range c.Audience {
		if item == audience {
			return true
		}
	}

	return false
}

func (c AuthContext) HasOrganization(organizationID string) bool {
	if organizationID == "" {
		return false
	}

	if c.OrganizationID == organizationID {
		return true
	}

	for _, item := range c.OrganizationIDs {
		if item == organizationID {
			return true
		}
	}

	return false
}

func (c AuthContext) RolesForOrganization(organizationID string) []string {
	roles := c.OrganizationRoles[organizationID]
	if len(roles) == 0 {
		return nil
	}

	copied := make([]string, len(roles))
	copy(copied, roles)
	return copied
}

func (c AuthContext) HasOrganizationRole(organizationID, role string) bool {
	for _, item := range c.OrganizationRoles[organizationID] {
		if item == role {
			return true
		}
	}

	return false
}
