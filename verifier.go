package codebird

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	config       Config
	discoveryURL string
	jwks         *jwksCache
}

func NewVerifier(config Config) (*Verifier, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidIssuer)
	}
	if config.Audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrInvalidAudience)
	}
	if config.JWKSTTL == 0 {
		config.JWKSTTL = 5 * time.Minute
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = 30 * time.Second
	}

	discoveryURL := strings.TrimRight(config.Issuer, "/") + "/.well-known/openid-configuration"

	return &Verifier{
		config:       config,
		discoveryURL: discoveryURL,
		jwks:         newJWKSCache(discoveryURL, config.JWKSTTL),
	}, nil
}

func (v *Verifier) VerifyAccessToken(_ context.Context, tokenString string) (AuthContext, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, fmt.Errorf("%w: unsupported signing algorithm", ErrInvalidToken)
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrInvalidToken)
		}

		return v.jwks.Key(kid)
	}, jwt.WithAudience(v.config.Audience), jwt.WithIssuer(v.config.Issuer), jwt.WithLeeway(v.config.ClockSkew))
	if err != nil {
		if isJWKSFetchError(err) {
			return AuthContext{}, err
		}
		return AuthContext{}, mapJWTError(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return AuthContext{}, fmt.Errorf("%w: invalid claims", ErrClaimsParseFailed)
	}

	return ParseAuthContext(map[string]any(claims))
}

func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fmt.Errorf("%w: %v", ErrTokenNotActive, err)
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return fmt.Errorf("%w: %v", ErrInvalidAudience, err)
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return fmt.Errorf("%w: %v", ErrInvalidIssuer, err)
	default:
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
}
