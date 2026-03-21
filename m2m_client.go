package codebird

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type M2MConfig struct {
	Endpoint       string
	ClientID       string
	ClientSecret   string
	Resource       string
	OrganizationID string
}

type M2MClient struct {
	config     M2MConfig
	httpClient *http.Client

	tokenMu sync.Mutex
	token   *m2mToken
}

func NewM2MClient(config M2MConfig) (*M2MClient, error) {
	switch {
	case strings.TrimSpace(config.Endpoint) == "":
		return nil, fmt.Errorf("%w: endpoint is required", ErrInvalidToken)
	case strings.TrimSpace(config.ClientID) == "":
		return nil, fmt.Errorf("%w: client id is required", ErrInvalidToken)
	case strings.TrimSpace(config.ClientSecret) == "":
		return nil, fmt.Errorf("%w: client secret is required", ErrInvalidToken)
	}

	return &M2MClient{
		config:     config,
		httpClient: http.DefaultClient,
	}, nil
}
