package codebird

type SessionContextUser struct {
	ID          string  `json:"id"`
	Username    *string `json:"username"`
	Name        *string `json:"name"`
	Email       *string `json:"email"`
	PhoneNumber *string `json:"phone_number"`
	Avatar      *string `json:"avatar"`
	UpdatedAt   int64   `json:"updated_at"`
}

type SessionContextApplication struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	TenantID string `json:"tenant_id"`
}

type SessionContextTenant struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type SessionContextOrganization struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	LogoURL  *string  `json:"logo_url"`
	IsMember bool     `json:"is_member"`
	IsAdmin  bool     `json:"is_admin"`
	Roles    []string `json:"roles"`
}

type SessionContextOrganizationSummary struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	LogoURL *string `json:"logo_url"`
}

type SessionContextSession struct {
	Subject               string   `json:"subject"`
	ClientID              *string  `json:"client_id"`
	Scopes                []string `json:"scopes"`
	CurrentOrganizationID *string  `json:"current_organization_id"`
}

type SessionContext struct {
	Tenant        *SessionContextTenant              `json:"tenant"`
	User          SessionContextUser                  `json:"user"`
	Application   *SessionContextApplication          `json:"application"`
	Organization  *SessionContextOrganization         `json:"organization"`
	Organizations []SessionContextOrganizationSummary `json:"organizations"`
	Session       SessionContextSession               `json:"session"`
}

type GetSessionContextOptions struct {
	OrganizationID string
}
