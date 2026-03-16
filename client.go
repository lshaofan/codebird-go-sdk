package codebird

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	endpoint   string
	httpClient *http.Client
}

func NewClient(config Config) (*Client, error) {
	if strings.TrimSpace(config.Issuer) == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidIssuer)
	}

	return &Client{
		endpoint:   strings.TrimRight(config.Issuer, "/"),
		httpClient: http.DefaultClient,
	}, nil
}

func (c *Client) GetSessionContext(ctx context.Context, accessToken string, opts *GetSessionContextOptions) (SessionContext, error) {
	if strings.TrimSpace(accessToken) == "" {
		return SessionContext{}, fmt.Errorf("%w: access token is required", ErrInvalidToken)
	}

	requestURL, err := url.Parse(c.endpoint + "/api/session/context")
	if err != nil {
		return SessionContext{}, err
	}
	if opts != nil && strings.TrimSpace(opts.OrganizationID) != "" {
		query := requestURL.Query()
		query.Set("organization_id", opts.OrganizationID)
		requestURL.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return SessionContext{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return SessionContext{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Message != "" {
			return SessionContext{}, fmt.Errorf("%w: %s", ErrInvalidToken, apiErr.Message)
		}
		return SessionContext{}, fmt.Errorf("%w: session context request failed", ErrInvalidToken)
	}

	var envelope struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Result  SessionContext `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return SessionContext{}, err
	}

	return envelope.Result, nil
}
