package codebird

import "errors"

var (
	ErrMissingAuthorizationHeader = errors.New("missing authorization header")
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header")
	ErrInvalidToken               = errors.New("invalid token")
	ErrInvalidIssuer              = errors.New("invalid issuer")
	ErrInvalidAudience            = errors.New("invalid audience")
	ErrTokenExpired               = errors.New("token expired")
	ErrTokenNotActive             = errors.New("token not active")
	ErrJWKSFetchFailed            = errors.New("jwks fetch failed")
	ErrClaimsParseFailed          = errors.New("claims parse failed")
)

func IsMissingAuthorizationHeader(err error) bool {
	return errors.Is(err, ErrMissingAuthorizationHeader)
}

func IsInvalidAuthorizationHeader(err error) bool {
	return errors.Is(err, ErrInvalidAuthorizationHeader)
}

func IsInvalidToken(err error) bool {
	return errors.Is(err, ErrInvalidToken)
}

func IsInvalidIssuer(err error) bool {
	return errors.Is(err, ErrInvalidIssuer)
}

func IsInvalidAudience(err error) bool {
	return errors.Is(err, ErrInvalidAudience)
}

func IsTokenExpired(err error) bool {
	return errors.Is(err, ErrTokenExpired)
}

func IsTokenNotActive(err error) bool {
	return errors.Is(err, ErrTokenNotActive)
}

func IsJWKSFetchFailed(err error) bool {
	return errors.Is(err, ErrJWKSFetchFailed)
}

func IsClaimsParseFailed(err error) bool {
	return errors.Is(err, ErrClaimsParseFailed)
}
