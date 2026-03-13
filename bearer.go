package codebird

import "strings"

func ParseBearerToken(header string) (string, error) {
	if strings.TrimSpace(header) == "" {
		return "", ErrMissingAuthorizationHeader
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", ErrInvalidAuthorizationHeader
	}

	return strings.TrimSpace(parts[1]), nil
}
