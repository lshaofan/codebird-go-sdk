package codebird

import (
	"fmt"
	"strings"
	"time"
)

func ParseAuthContext(claims map[string]any) (AuthContext, error) {
	ctx := AuthContext{
		OrganizationRoles: map[string][]string{},
		RawClaims:         claims,
	}

	if subject, ok := claims["sub"].(string); ok {
		ctx.Subject = subject
	}
	if issuer, ok := claims["iss"].(string); ok {
		ctx.Issuer = issuer
	}
	if email, ok := claims["email"].(string); ok {
		ctx.Email = email
	}
	if username, ok := claims["username"].(string); ok {
		ctx.Username = username
	}
	if name, ok := claims["name"].(string); ok {
		ctx.Name = name
	}
	if phoneNumber, ok := claims["phone_number"].(string); ok {
		ctx.PhoneNumber = phoneNumber
	}
	if organizationID, ok := claims["organization_id"].(string); ok {
		ctx.OrganizationID = organizationID
	}
	if organizationIsAdmin, ok := claims["organization_is_admin"].(bool); ok {
		ctx.OrganizationIsAdmin = organizationIsAdmin
	}
	if organizations, ok := claims["organizations"].([]any); ok {
		for _, organization := range organizations {
			value, ok := organization.(string)
			if ok {
				ctx.OrganizationIDs = append(ctx.OrganizationIDs, value)
			}
		}
	}
	if roles, ok := claims["organization_roles"].(map[string]any); ok {
		for key, value := range roles {
			items, ok := value.([]any)
			if !ok {
				return AuthContext{}, fmt.Errorf("%w: invalid organization roles", ErrClaimsParseFailed)
			}

			for _, item := range items {
				role, ok := item.(string)
				if ok {
					ctx.OrganizationRoles[key] = append(ctx.OrganizationRoles[key], role)
				}
			}
		}
	}
	if roleItems, ok := claims["organization_roles"].([]any); ok {
		for _, item := range roleItems {
			roleValue, ok := item.(string)
			if !ok {
				return AuthContext{}, fmt.Errorf("%w: invalid organization roles", ErrClaimsParseFailed)
			}

			orgID, roleName, found := strings.Cut(roleValue, ":")
			if !found || orgID == "" || roleName == "" {
				return AuthContext{}, fmt.Errorf("%w: invalid organization roles", ErrClaimsParseFailed)
			}

			ctx.OrganizationRoles[orgID] = append(ctx.OrganizationRoles[orgID], roleName)
		}
	}
	if audience, ok := claims["aud"].(string); ok {
		ctx.Audience = []string{audience}
	}
	if audiences, ok := claims["aud"].([]any); ok {
		for _, audience := range audiences {
			value, ok := audience.(string)
			if ok {
				ctx.Audience = append(ctx.Audience, value)
			}
		}
	}
	if exp, ok := unixClaim(claims["exp"]); ok {
		ctx.ExpiresAt = exp
	}
	if nbf, ok := unixClaim(claims["nbf"]); ok {
		ctx.NotBefore = &nbf
	}

	return ctx, nil
}

func unixClaim(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case float64:
		return time.Unix(int64(typed), 0), true
	case int64:
		return time.Unix(typed, 0), true
	case int:
		return time.Unix(int64(typed), 0), true
	default:
		return time.Time{}, false
	}
}
