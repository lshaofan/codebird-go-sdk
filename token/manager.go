package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type keyMaterial struct {
	signingMethod jwt.SigningMethod
	privateKey    interface{}
	publicKey     interface{}
	version       time.Time
}

type cacheKey struct {
	id             uint
	requirePrivate bool
}

// Manager 负责基于证书的 JWT 签发与校验
type Manager struct {
	provider   CertificateProvider
	keyCache   sync.Map
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewManager 构建带默认配置的管理器
func NewManager(opts ...Option) *Manager {
	m := &Manager{
		accessTTL:  time.Hour,
		refreshTTL: 7 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// GenerateTokenPair 基于证书签发访问令牌与刷新令牌
func (m *Manager) GenerateTokenPair(user *User, cert *Certificate, meta TokenMeta) (*TokenPair, error) {
	if user == nil || user.ID == 0 {
		return nil, errors.New("invalid user")
	}
	if cert == nil || cert.ID == 0 {
		return nil, ErrCertificateNotConfigured
	}
	if err := m.ensureCertificateUsable(cert); err != nil {
		return nil, err
	}

	meta = normalizeMeta(meta, cert)
	keyMat, err := m.getKeyMaterial(cert, true)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	// 优先使用 Meta 中的 TTL，否则使用 Manager 默认值
	accessTTL := m.accessTTL
	if meta.AccessTTL > 0 {
		accessTTL = meta.AccessTTL
	}
	refreshTTL := m.refreshTTL
	if meta.RefreshTTL > 0 {
		refreshTTL = meta.RefreshTTL
	}
	accessExpireAt := now.Add(accessTTL)
	refreshExpireAt := now.Add(refreshTTL)
	userCopy := cloneUser(user)

	accessClaims := m.buildClaims(userCopy, meta, TokenKindAccess, "", accessExpireAt, now)
	accessToken, err := m.signToken(accessClaims, keyMat, meta.CertificateID)
	if err != nil {
		return nil, err
	}

	refreshClaims := m.buildClaims(userCopy, meta, TokenKindRefresh, accessToken, refreshExpireAt, now)
	refreshToken, err := m.signToken(refreshClaims, keyMat, meta.CertificateID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExpireAt,
		RefreshTokenExpiresAt: refreshExpireAt,
	}, nil
}

// ParseToken 解析并验证令牌，返回 Claims 与对应证书
func (m *Manager) ParseToken(ctx context.Context, tokenString string) (*Claims, *Certificate, error) {
	claims := &Claims{}
	var certificate *Certificate

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		kid, err := parseKeyID(t.Header["kid"])
		if err != nil {
			return nil, err
		}

		cert, err := m.getCertificate(ctx, kid)
		if err != nil {
			return nil, err
		}
		if cert == nil || cert.ID == 0 {
			return nil, ErrCertificateNotConfigured
		}
		if err := m.ensureCertificateUsable(cert); err != nil {
			return nil, err
		}

		keyMat, err := m.getKeyMaterial(cert, false)
		if err != nil {
			return nil, err
		}
		if t.Method.Alg() != keyMat.signingMethod.Alg() {
			return nil, ErrTokenSignatureMethod
		}
		certificate = cert
		return keyMat.publicKey, nil
	})
	if err != nil {
		return nil, nil, err
	}
	if !token.Valid {
		return nil, nil, errors.New("invalid token")
	}
	return claims, certificate, nil
}

// ValidateToken 仅校验令牌有效性
func (m *Manager) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, _, err := m.ParseToken(ctx, tokenString)
	return claims, err
}

func (m *Manager) buildClaims(user *User, meta TokenMeta, tokenKind string, associatedAccessToken string, expireAt time.Time, now time.Time) *Claims {
	audience := jwt.ClaimStrings(meta.Audience)
	if len(audience) == 0 {
		audience = jwt.ClaimStrings{tokenAudiencePlaceholder}
	}

	claims := &Claims{
		User:              user,
		AccessToken:       associatedAccessToken,
		TokenType:         TokenTypeBearer,
		RefreshTokenType:  tokenKind,
		SigninMethod:      meta.SigninMethod,
		ApplicationID:     meta.ApplicationID,
		ApplicationClient: meta.ApplicationClientID,
		ApplicationName:   meta.ApplicationName,
		OrganizationID:    meta.OrganizationID,
		OrganizationCode:  meta.OrganizationCode,
		CertificateID:     meta.CertificateID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    meta.Issuer,
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(expireAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	if tokenKind == TokenKindAccess {
		claims.AccessToken = ""
	}

	return claims
}

func (m *Manager) signToken(claims *Claims, keyMat *keyMaterial, certificateID uint) (string, error) {
	if keyMat.privateKey == nil {
		return "", ErrInvalidPrivateKey
	}
	token := jwt.NewWithClaims(keyMat.signingMethod, claims)
	token.Header["kid"] = strconv.FormatUint(uint64(certificateID), 10)
	return token.SignedString(keyMat.privateKey)
}

func (m *Manager) ensureCertificateUsable(cert *Certificate) error {
	if cert.PrivateKey == "" && cert.Certificate == "" {
		return ErrInvalidCertificate
	}
	if !cert.ExpiresAt.IsZero() && time.Now().After(cert.ExpiresAt) {
		return ErrCertificateExpired
	}
	return nil
}

func (m *Manager) getCertificate(ctx context.Context, id uint) (*Certificate, error) {
	if m.provider == nil {
		return nil, ErrCertificateNotConfigured
	}
	return m.provider.GetByID(ctx, id)
}

func (m *Manager) getKeyMaterial(cert *Certificate, requirePrivate bool) (*keyMaterial, error) {
	key := cacheKey{
		id:             cert.ID,
		requirePrivate: requirePrivate,
	}
	if value, ok := m.keyCache.Load(key); ok {
		if km, ok := value.(*keyMaterial); ok {
			if km.version.Equal(cert.UpdatedAt) || cert.UpdatedAt.IsZero() {
				return km, nil
			}
		}
	}

	keyMat, err := buildKeyMaterial(cert, requirePrivate)
	if err != nil {
		return nil, err
	}
	m.keyCache.Store(key, keyMat)
	return keyMat, nil
}

func buildKeyMaterial(cert *Certificate, requirePrivate bool) (*keyMaterial, error) {
	signingMethod, err := resolveSigningMethod(cert.Algorithm)
	if err != nil {
		return nil, err
	}

	var privateKey interface{}
	if cert.PrivateKey != "" {
		privateKey, err = parsePrivateKey(cert.PrivateKey, signingMethod)
		if err != nil {
			return nil, err
		}
	} else if requirePrivate {
		return nil, ErrInvalidPrivateKey
	}

	publicKey, err := parsePublicKey(cert.Certificate, signingMethod)
	if err != nil {
		return nil, err
	}

	return &keyMaterial{
		signingMethod: signingMethod,
		privateKey:    privateKey,
		publicKey:     publicKey,
		version:       cert.UpdatedAt,
	}, nil
}

func resolveSigningMethod(algorithm string) (jwt.SigningMethod, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "RS256":
		return jwt.SigningMethodRS256, nil
	case "RS384":
		return jwt.SigningMethodRS384, nil
	case "RS512":
		return jwt.SigningMethodRS512, nil
	case "ES256":
		return jwt.SigningMethodES256, nil
	case "ES384":
		return jwt.SigningMethodES384, nil
	case "ES512":
		return jwt.SigningMethodES512, nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func parsePrivateKey(pemString string, method jwt.SigningMethod) (interface{}, error) {
	if pemString == "" {
		return nil, ErrInvalidPrivateKey
	}
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, ErrInvalidPrivateKey
	}

	keyBytes := block.Bytes
	switch method {
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
		if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
			return key, nil
		}
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, ErrInvalidPrivateKey
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		key, err := x509.ParseECPrivateKey(keyBytes)
		if err == nil {
			return key, nil
		}
		parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		if ecKey, ok := parsed.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, ErrInvalidPrivateKey
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func parsePublicKey(pemString string, method jwt.SigningMethod) (interface{}, error) {
	rest := []byte(pemString)
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remaining
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if strings.HasPrefix(method.Alg(), "RS") {
				return pub, nil
			}
		case *ecdsa.PublicKey:
			if strings.HasPrefix(method.Alg(), "ES") && validCurveForMethod(pub.Curve, method) {
				return pub, nil
			}
		default:
			return nil, ErrUnsupportedAlgorithm
		}

		rest = remaining
	}
	return nil, ErrInvalidCertificate
}

func validCurveForMethod(curve elliptic.Curve, method jwt.SigningMethod) bool {
	switch method {
	case jwt.SigningMethodES256:
		return curve == elliptic.P256()
	case jwt.SigningMethodES384:
		return curve == elliptic.P384()
	case jwt.SigningMethodES512:
		return curve == elliptic.P521()
	default:
		return false
	}
}

func parseKeyID(raw interface{}) (uint, error) {
	switch v := raw.(type) {
	case string:
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, ErrMissingKeyID
		}
		return uint(id), nil
	case float64:
		return uint(v), nil
	case json.Number:
		id, err := strconv.ParseUint(v.String(), 10, 64)
		if err != nil {
			return 0, ErrMissingKeyID
		}
		return uint(id), nil
	default:
		return 0, ErrMissingKeyID
	}
}

func cloneUser(user *User) *User {
	if user == nil {
		return nil
	}
	clone := *user
	return &clone
}

func normalizeMeta(meta TokenMeta, cert *Certificate) TokenMeta {
	if meta.CertificateID == 0 && cert != nil {
		meta.CertificateID = cert.ID
	}
	if meta.SigninMethod == "" {
		meta.SigninMethod = DefaultSigninMethod
	}
	if meta.Issuer == "" {
		builder := []string{defaultIssuerPrefix}
		if meta.OrganizationCode != "" {
			builder = append(builder, meta.OrganizationCode)
		}
		if meta.ApplicationClientID != "" {
			builder = append(builder, meta.ApplicationClientID)
		}
		meta.Issuer = strings.Join(builder, ":")
	}
	if len(meta.Audience) == 0 {
		if meta.ApplicationClientID != "" {
			meta.Audience = []string{meta.ApplicationClientID}
		} else {
			meta.Audience = []string{tokenAudiencePlaceholder}
		}
	}
	return meta
}
