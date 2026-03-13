package codebird

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiEnvelope[T any] struct {
	Code    int    `json:"code"`
	Result  T      `json:"result"`
	Message string `json:"message"`
}

type organizationMemberPayload struct {
	ID           string  `json:"id"`
	Username     *string `json:"username"`
	PrimaryPhone *string `json:"primary_phone"`
	PrimaryEmail *string `json:"primary_email"`
	Name         *string `json:"name"`
	IsAdmin      bool    `json:"is_admin"`
	JoinedAt     string  `json:"joined_at"`
	CreatedAt    string  `json:"created_at"`
}

type organizationMembersPagePayload struct {
	Total    int64                       `json:"total"`
	Data     []organizationMemberPayload `json:"data"`
	Page     int                         `json:"page"`
	PageSize int                         `json:"page_size"`
}

type organizationMemberRolePayload struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Type        string  `json:"type"`
	CreatedAt   string  `json:"created_at"`
}

func (c *M2MClient) ListOrganizationMembers(ctx context.Context, organizationID string, input ListOrganizationMembersInput) (*OrganizationMembersPage, error) {
	values := url.Values{}
	if input.Page > 0 {
		values.Set("page", fmt.Sprintf("%d", input.Page))
	}
	if input.PageSize > 0 {
		values.Set("page_size", fmt.Sprintf("%d", input.PageSize))
	}
	if input.Phone != "" {
		values.Set("phone", input.Phone)
	}
	if input.Name != "" {
		values.Set("name", input.Name)
	}
	if input.IsAdmin != nil {
		values.Set("is_admin", fmt.Sprintf("%t", *input.IsAdmin))
	}

	var envelope apiEnvelope[organizationMembersPagePayload]
	if err := c.doJSONRequest(ctx, http.MethodGet, "/api/v1/m2m/organizations/"+organizationID+"/members", values, nil, &envelope); err != nil {
		return nil, err
	}

	items := make([]OrganizationMember, 0, len(envelope.Result.Data))
	for _, item := range envelope.Result.Data {
		items = append(items, toOrganizationMember(item))
	}

	return &OrganizationMembersPage{
		Total:    envelope.Result.Total,
		Data:     items,
		Page:     envelope.Result.Page,
		PageSize: envelope.Result.PageSize,
	}, nil
}

func (c *M2MClient) AddOrganizationMember(ctx context.Context, organizationID string, input AddOrganizationMemberInput) (*OrganizationMember, error) {
	payload := map[string]any{
		"phone": input.Phone,
	}
	if input.Name != "" {
		payload["name"] = input.Name
	}
	if input.Email != "" {
		payload["email"] = input.Email
	}

	var envelope apiEnvelope[organizationMemberPayload]
	if err := c.doJSONRequest(ctx, http.MethodPost, "/api/v1/m2m/organizations/"+organizationID+"/members", nil, payload, &envelope); err != nil {
		return nil, err
	}

	member := toOrganizationMember(envelope.Result)
	return &member, nil
}

func (c *M2MClient) RemoveOrganizationMember(ctx context.Context, organizationID, userID string) error {
	return c.doJSONRequest(ctx, http.MethodDelete, "/api/v1/m2m/organizations/"+organizationID+"/members/"+userID, nil, nil, nil)
}

func (c *M2MClient) GetOrganizationMemberRoles(ctx context.Context, organizationID, userID string) ([]OrganizationMemberRole, error) {
	var envelope apiEnvelope[[]organizationMemberRolePayload]
	if err := c.doJSONRequest(ctx, http.MethodGet, "/api/v1/m2m/organizations/"+organizationID+"/members/"+userID+"/roles", nil, nil, &envelope); err != nil {
		return nil, err
	}

	roles := make([]OrganizationMemberRole, 0, len(envelope.Result))
	for _, item := range envelope.Result {
		createdAt, _ := parseRFC3339(item.CreatedAt)
		roles = append(roles, OrganizationMemberRole{
			ID:          item.ID,
			Name:        item.Name,
			Description: item.Description,
			Type:        item.Type,
			CreatedAt:   createdAt,
		})
	}

	return roles, nil
}

func (c *M2MClient) UpdateOrganizationMemberRoles(ctx context.Context, organizationID, userID string, input UpdateOrganizationMemberRolesInput) error {
	payload := map[string]any{
		"role_ids": input.RoleIDs,
	}

	return c.doJSONRequest(ctx, http.MethodPut, "/api/v1/m2m/organizations/"+organizationID+"/members/"+userID+"/roles", nil, payload, nil)
}

func (c *M2MClient) doJSONRequest(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	var requestBody *bytes.Reader
	if body == nil {
		requestBody = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		requestBody = bytes.NewReader(data)
	}

	requestURL := strings.TrimRight(c.config.Endpoint, "/") + path
	if encoded := query.Encode(); encoded != "" {
		requestURL += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, requestBody)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: unexpected status %d", ErrInvalidToken, resp.StatusCode)
	}

	if out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	return nil
}

func toOrganizationMember(item organizationMemberPayload) OrganizationMember {
	joinedAt, _ := parseRFC3339(item.JoinedAt)
	createdAt, _ := parseRFC3339(item.CreatedAt)

	return OrganizationMember{
		ID:           item.ID,
		Username:     item.Username,
		PrimaryPhone: item.PrimaryPhone,
		PrimaryEmail: item.PrimaryEmail,
		Name:         item.Name,
		IsAdmin:      item.IsAdmin,
		JoinedAt:     joinedAt,
		CreatedAt:    createdAt,
	}
}

func parseRFC3339(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	return time.Parse(time.RFC3339, value)
}
