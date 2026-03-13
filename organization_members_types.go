package codebird

import "time"

type ListOrganizationMembersInput struct {
	Page     int
	PageSize int
	Phone    string
	Name     string
	IsAdmin  *bool
}

type OrganizationMember struct {
	ID           string
	Username     *string
	PrimaryPhone *string
	PrimaryEmail *string
	Name         *string
	IsAdmin      bool
	JoinedAt     time.Time
	CreatedAt    time.Time
}

type OrganizationMembersPage struct {
	Total    int64
	Data     []OrganizationMember
	Page     int
	PageSize int
}

type AddOrganizationMemberInput struct {
	Phone string
	Name  string
	Email string
}

type OrganizationMemberRole struct {
	ID          string
	Name        string
	Description *string
	Type        string
	CreatedAt   time.Time
}

type UpdateOrganizationMemberRolesInput struct {
	RoleIDs []string
}
