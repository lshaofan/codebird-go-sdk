package codebird

import "time"

type Config struct {
	Issuer    string
	Audience  string
	JWKSTTL   time.Duration
	ClockSkew time.Duration
}
