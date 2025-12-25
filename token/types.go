package token

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	TokenTypeBearer          = "Bearer"
	TokenKindAccess          = "access-token"
	TokenKindRefresh         = "refresh-token"
	DefaultSigninMethod      = "password"
	defaultIssuerPrefix      = "codebird"
	tokenAudiencePlaceholder = "codebird-client"
)

// Certificate 用于签发/验签的证书数据
type Certificate struct {
	ID          uint
	Algorithm   string
	Certificate string
	PrivateKey  string
	ExpiresAt   time.Time
	UpdatedAt   time.Time
}

// TokenMeta 生成令牌时的上下文信息
type TokenMeta struct {
	ApplicationID       uint
	ApplicationClientID string
	ApplicationName     string
	OrganizationID      uint
	OrganizationCode    string
	CertificateID       uint
	SigninMethod        string
	Issuer              string
	Audience            []string
	// TTL 配置（可选，为 0 时使用 Manager 默认值）
	AccessTTL  time.Duration // Access Token 有效期
	RefreshTTL time.Duration // Refresh Token 有效期
}

// TokenPair 表示访问令牌与刷新令牌
type TokenPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// User 表示令牌中的用户公开信息（与后端 Claims 兼容的精简版）
type User struct {
	ID            uint           `json:"ID"`
	Username      string         `json:"username,omitempty"`
	Phone         string         `json:"phone,omitempty"`
	Nickname      string         `json:"nickname,omitempty"`
	Introduction  string         `json:"introduction,omitempty"`
	Avatar        string         `json:"avatar,omitempty"`
	Email         string         `json:"email,omitempty"`
	Gender        uint           `json:"gender,omitempty"`
	Status        uint           `json:"status,omitempty"`
	IsSuper       bool           `json:"is_super,omitempty"`
	Organizations []Organization `json:"organizations,omitempty"`
	LastLoginTime string         `json:"last_login_time,omitempty"`
	LastLoginIP   string         `json:"last_login_ip,omitempty"`
	LoginCount    int            `json:"login_count,omitempty"`
}

// Organization 表示令牌中的组织信息
type Organization struct {
	ID   uint   `json:"id"`
	Code string `json:"code,omitempty"`
	Name string `json:"name,omitempty"`
}

// Claims 为 JWT 携带的完整信息
type Claims struct {
	User              *User  `json:"user"`
	AccessToken       string `json:"accessToken,omitempty"`
	TokenType         string `json:"tokenType"`
	RefreshTokenType  string `json:"refreshTokenType"`
	SigninMethod      string `json:"signinMethod"`
	ApplicationID     uint   `json:"applicationId"`
	ApplicationClient string `json:"applicationClientId"`
	ApplicationName   string `json:"applicationName,omitempty"`
	OrganizationID    uint   `json:"organizationId"`
	OrganizationCode  string `json:"organizationCode"`
	CertificateID     uint   `json:"certificateId"`
	jwt.RegisteredClaims
}

func (c *Claims) IsAccessToken() bool {
	return c.RefreshTokenType == TokenKindAccess
}

func (c *Claims) IsRefreshToken() bool {
	return c.RefreshTokenType == TokenKindRefresh
}
