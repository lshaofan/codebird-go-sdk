package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JWKKey 表示 JWKS 单条记录
type JWKKey struct {
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

// JWKSResponse JWKS 响应
type JWKSResponse struct {
	Keys []JWKKey `json:"keys"`
}

// HTTPJWKSProvider 通过 HTTP 拉取 JWKS 的证书提供方
type HTTPJWKSProvider struct {
	endpoint  string
	client    *http.Client
	ttl       time.Duration
	mu        sync.RWMutex
	cache     map[uint]*Certificate
	fetchedAt time.Time
}

// HTTPJWKSOption 配置项
type HTTPJWKSOption func(*HTTPJWKSProvider)

// WithHTTPClient 自定义 HTTP 客户端
func WithHTTPClient(c *http.Client) HTTPJWKSOption {
	return func(p *HTTPJWKSProvider) {
		p.client = c
	}
}

// WithJWKSCacheTTL 配置 JWKS 缓存时间
func WithJWKSCacheTTL(ttl time.Duration) HTTPJWKSOption {
	return func(p *HTTPJWKSProvider) {
		p.ttl = ttl
	}
}

// NewHTTPJWKSProvider 构建 HTTP JWKS Provider
func NewHTTPJWKSProvider(endpoint string, opts ...HTTPJWKSOption) *HTTPJWKSProvider {
	p := &HTTPJWKSProvider{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   http.DefaultClient,
		ttl:      5 * time.Minute,
		cache:    make(map[uint]*Certificate),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *HTTPJWKSProvider) GetByID(ctx context.Context, id uint) (*Certificate, error) {
	if cert := p.getFromCache(id); cert != nil {
		return cert, nil
	}

	if err := p.refresh(ctx); err != nil {
		return nil, err
	}

	if cert := p.getFromCache(id); cert != nil {
		return cert, nil
	}

	return nil, ErrCertificateNotConfigured
}

func (p *HTTPJWKSProvider) getFromCache(id uint) *Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.ttl > 0 && !p.fetchedAt.IsZero() && time.Since(p.fetchedAt) > p.ttl {
		return nil
	}
	return p.cache[id]
}

func (p *HTTPJWKSProvider) refresh(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 双检：可能其它并发已经刷新
	if p.ttl > 0 && !p.fetchedAt.IsZero() && time.Since(p.fetchedAt) <= p.ttl {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("fetch jwks failed with status " + resp.Status)
	}

	var payload JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	cache := make(map[uint]*Certificate, len(payload.Keys))
	for _, key := range payload.Keys {
		cert, err := jwkToCertificate(key)
		if err != nil {
			return err
		}
		cache[cert.ID] = cert
	}

	p.cache = cache
	p.fetchedAt = time.Now()
	return nil
}

func jwkToCertificate(key JWKKey) (*Certificate, error) {
	id, err := strconv.ParseUint(key.Kid, 10, 64)
	if err != nil {
		return nil, ErrMissingKeyID
	}

	alg := strings.ToUpper(strings.TrimSpace(key.Alg))

	if len(key.X5c) == 0 {
		return nil, ErrInvalidCertificate
	}
	der, err := base64.StdEncoding.DecodeString(key.X5c[0])
	if err != nil {
		return nil, err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
	return &Certificate{
		ID:          uint(id),
		Algorithm:   alg,
		Certificate: pemStr,
	}, nil
}
