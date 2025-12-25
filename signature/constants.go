package signature

import "time"

// HTTP Header 常量
const (
	HeaderClientID  = "X-App-Client-ID"
	HeaderTimestamp = "X-App-Timestamp"
	HeaderNonce     = "X-App-Nonce"
	HeaderSignature = "X-App-Signature"
)

// 安全配置常量
const (
	// TimestampTolerance 时间戳容差（±5分钟）
	TimestampTolerance = 300 * time.Second

	// NonceExpiration Nonce 过期时间（10分钟）
	NonceExpiration = 10 * time.Minute

	// NonceLength Nonce 长度
	NonceLength = 32
)

// 支持的签名算法
const (
	AlgorithmRS256 = "RS256"
	AlgorithmRS384 = "RS384"
	AlgorithmRS512 = "RS512"
	AlgorithmES256 = "ES256"
	AlgorithmES384 = "ES384"
	AlgorithmES512 = "ES512"
)

// AllowedAlgorithms 允许的签名算法（非对称加密）
var AllowedAlgorithms = map[string]bool{
	AlgorithmRS256: true,
	AlgorithmRS384: true,
	AlgorithmRS512: true,
	AlgorithmES256: true,
	AlgorithmES384: true,
	AlgorithmES512: true,
}

// IsAllowedAlgorithm 检查算法是否允许
func IsAllowedAlgorithm(alg string) bool {
	return AllowedAlgorithms[alg]
}
