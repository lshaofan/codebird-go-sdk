package token

import (
	"context"
	"time"
)

// CertificateProvider 抽象证书来源（数据库、远程接口、本地文件等）
type CertificateProvider interface {
	GetByID(ctx context.Context, id uint) (*Certificate, error)
}

// Option 配置 Token 管理器
type Option func(*Manager)

// WithCertificateProvider 设置证书提供方
func WithCertificateProvider(p CertificateProvider) Option {
	return func(m *Manager) {
		m.provider = p
	}
}

// WithAccessTTL 配置访问令牌有效期
func WithAccessTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		m.accessTTL = ttl
	}
}

// WithRefreshTTL 配置刷新令牌有效期
func WithRefreshTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		m.refreshTTL = ttl
	}
}
