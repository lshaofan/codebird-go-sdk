package codebird

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultM2MExpirySkew = 30 * time.Second

type m2mToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

type m2mTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *M2MClient) getToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.token != nil && c.token.AccessToken != "" && c.token.ExpiresAt.After(time.Now().Add(defaultM2MExpirySkew)) {
		return c.token.AccessToken, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.config.ClientID)
	form.Set("client_secret", c.config.ClientSecret)
	if c.config.Resource != "" {
		form.Set("resource", c.config.Resource)
	}
	if c.config.OrganizationID != "" {
		form.Set("organization_id", c.config.OrganizationID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.Endpoint, "/")+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("%w: unexpected status %d", ErrInvalidToken, resp.StatusCode)
	}

	var payload m2mTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("%w: missing access token", ErrInvalidToken)
	}

	expiresIn := time.Duration(payload.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}

	c.token = &m2mToken{
		AccessToken: payload.AccessToken,
		ExpiresAt:   time.Now().Add(expiresIn),
	}

	return payload.AccessToken, nil
}
