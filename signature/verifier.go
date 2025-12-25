package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingHeader       = errors.New("missing required header")
	ErrInvalidSignature    = errors.New("invalid signature format")
	ErrSignatureVerifyFail = errors.New("signature verification failed")
	ErrTimestampExpired    = errors.New("timestamp expired")
	ErrNonceReused         = errors.New("nonce has been used")
	ErrNilPublicKey        = errors.New("public key is nil")
)

// PublicKeyProvider 公钥提供者函数
// 参数: clientID（客户端ID）, keyID（证书ID）
// 返回: 公钥, 错误
type PublicKeyProvider func(clientID, keyID string) (crypto.PublicKey, error)

// NonceChecker Nonce 检查函数
// 参数: clientID（客户端ID）, nonce（随机字符串）
// 返回: 是否已使用, 错误
type NonceChecker func(clientID, nonce string) (used bool, err error)

// NonceSaver Nonce 保存函数
// 参数: clientID（客户端ID）, nonce（随机字符串）, ttl（过期时间）
// 返回: 错误
type NonceSaver func(clientID, nonce string, ttl time.Duration) error

// VerifierConfig 验证器配置
type VerifierConfig struct {
	PublicKeyProvider PublicKeyProvider // 获取公钥的回调函数
	NonceChecker      NonceChecker      // 检查 Nonce 是否已使用
	NonceSaver        NonceSaver        // 保存 Nonce
	TimestampTolerance time.Duration    // 时间戳容差，默认 5 分钟
}

// Verifier 签名验证器
type Verifier struct {
	config VerifierConfig
}

// VerifyParams 验证参数
type VerifyParams struct {
	ClientID  string
	Timestamp int64
	Nonce     string
	Signature string
	Method    string
	Path      string
	Body      []byte
}

// VerifyResult 验证结果
type VerifyResult struct {
	Valid     bool   // 是否有效
	ClientID  string // 客户端 ID
	KeyID     string // 证书 ID
	Algorithm string // 签名算法
	Error     error  // 错误信息
}

// NewVerifier 创建验证器
func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.TimestampTolerance == 0 {
		cfg.TimestampTolerance = TimestampTolerance
	}
	return &Verifier{config: cfg}
}

// VerifyRequest 验证 HTTP 请求签名
func (v *Verifier) VerifyRequest(req *http.Request) (*VerifyResult, error) {
	// 读取请求体
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		// 重新设置请求体
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// 提取 Header
	clientID := req.Header.Get(HeaderClientID)
	if clientID == "" {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("%w: %s", ErrMissingHeader, HeaderClientID)}, nil
	}

	timestampStr := req.Header.Get(HeaderTimestamp)
	if timestampStr == "" {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("%w: %s", ErrMissingHeader, HeaderTimestamp)}, nil
	}
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("invalid timestamp: %w", err)}, nil
	}

	nonce := req.Header.Get(HeaderNonce)
	if nonce == "" {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("%w: %s", ErrMissingHeader, HeaderNonce)}, nil
	}

	signature := req.Header.Get(HeaderSignature)
	if signature == "" {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("%w: %s", ErrMissingHeader, HeaderSignature)}, nil
	}

	return v.Verify(&VerifyParams{
		ClientID:  clientID,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
		Method:    req.Method,
		Path:      req.URL.Path,
		Body:      body,
	})
}

// Verify 验证签名
func (v *Verifier) Verify(params *VerifyParams) (*VerifyResult, error) {
	result := &VerifyResult{
		Valid:    false,
		ClientID: params.ClientID,
	}

	// 1. 验证时间戳
	if err := v.validateTimestamp(params.Timestamp); err != nil {
		result.Error = err
		return result, nil
	}

	// 2. 检查 Nonce（防重放）
	if v.config.NonceChecker != nil {
		used, err := v.config.NonceChecker(params.ClientID, params.Nonce)
		if err != nil {
			return nil, fmt.Errorf("nonce check failed: %w", err)
		}
		if used {
			result.Error = ErrNonceReused
			return result, nil
		}
	}

	// 3. 解析签名格式: {algorithm}.{kid}.{signature_base64}
	algorithm, keyID, signatureBytes, err := v.parseSignature(params.Signature)
	if err != nil {
		result.Error = err
		return result, nil
	}
	result.Algorithm = algorithm
	result.KeyID = keyID

	// 4. 验证算法是否允许
	if !IsAllowedAlgorithm(algorithm) {
		result.Error = fmt.Errorf("unsupported algorithm: %s", algorithm)
		return result, nil
	}

	// 5. 获取公钥
	if v.config.PublicKeyProvider == nil {
		return nil, errors.New("public key provider is required")
	}
	publicKey, err := v.config.PublicKeyProvider(params.ClientID, keyID)
	if err != nil {
		result.Error = fmt.Errorf("failed to get public key: %w", err)
		return result, nil
	}
	if publicKey == nil {
		result.Error = ErrNilPublicKey
		return result, nil
	}

	// 6. 构建规范化请求
	canonical := BuildCanonicalRequest(
		params.ClientID,
		params.Timestamp,
		params.Nonce,
		params.Method,
		params.Path,
		params.Body,
	)

	// 7. 验证签名
	if err := v.verifySignature(publicKey, algorithm, canonical.Hash(), signatureBytes); err != nil {
		result.Error = ErrSignatureVerifyFail
		return result, nil
	}

	// 8. 保存 Nonce（防重放）
	if v.config.NonceSaver != nil {
		if err := v.config.NonceSaver(params.ClientID, params.Nonce, NonceExpiration); err != nil {
			return nil, fmt.Errorf("nonce save failed: %w", err)
		}
	}

	result.Valid = true
	return result, nil
}

// validateTimestamp 验证时间戳
func (v *Verifier) validateTimestamp(timestamp int64) error {
	now := time.Now().Unix()
	diff := now - timestamp
	tolerance := int64(v.config.TimestampTolerance.Seconds())

	if diff < -tolerance || diff > tolerance {
		return fmt.Errorf("%w: difference is %d seconds", ErrTimestampExpired, diff)
	}
	return nil
}

// parseSignature 解析签名格式
func (v *Verifier) parseSignature(signature string) (algorithm, keyID string, signatureBytes []byte, err error) {
	parts := strings.Split(signature, ".")
	if len(parts) != 3 {
		return "", "", nil, fmt.Errorf("%w: expected format {algorithm}.{kid}.{signature}", ErrInvalidSignature)
	}

	algorithm = parts[0]
	keyID = parts[1]
	signatureBytes, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: invalid base64 encoding", ErrInvalidSignature)
	}

	return algorithm, keyID, signatureBytes, nil
}

// verifySignature 验证签名
func (v *Verifier) verifySignature(publicKey crypto.PublicKey, algorithm string, data, signature []byte) error {
	hashFunc := getHashFunc(algorithm)

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, hashFunc, data, signature)

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, data, signature) {
			return ErrSignatureVerifyFail
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// ExtractHeadersFromRequest 从请求中提取签名相关的 Header
func ExtractHeadersFromRequest(req *http.Request) (clientID string, timestamp int64, nonce, signature string, err error) {
	clientID = req.Header.Get(HeaderClientID)
	if clientID == "" {
		return "", 0, "", "", fmt.Errorf("%w: %s", ErrMissingHeader, HeaderClientID)
	}

	timestampStr := req.Header.Get(HeaderTimestamp)
	if timestampStr == "" {
		return "", 0, "", "", fmt.Errorf("%w: %s", ErrMissingHeader, HeaderTimestamp)
	}
	timestamp, err = strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", 0, "", "", fmt.Errorf("invalid timestamp: %w", err)
	}

	nonce = req.Header.Get(HeaderNonce)
	if nonce == "" {
		return "", 0, "", "", fmt.Errorf("%w: %s", ErrMissingHeader, HeaderNonce)
	}

	signature = req.Header.Get(HeaderSignature)
	if signature == "" {
		return "", 0, "", "", fmt.Errorf("%w: %s", ErrMissingHeader, HeaderSignature)
	}

	return clientID, timestamp, nonce, signature, nil
}
