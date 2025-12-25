package token

import "errors"

var (
	ErrCertificateNotConfigured = errors.New("certificate not configured")
	ErrCertificateExpired       = errors.New("certificate expired")
	ErrInvalidPrivateKey        = errors.New("invalid private key")
	ErrInvalidCertificate       = errors.New("invalid certificate")
	ErrUnsupportedAlgorithm     = errors.New("unsupported algorithm")
	ErrMissingKeyID             = errors.New("missing kid header")
	ErrTokenSignatureMethod     = errors.New("token signing method mismatch")
)
