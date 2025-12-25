package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

var (
	ErrNilPrivateKey     = errors.New("private key is nil")
	ErrUnsupportedSigner = errors.New("unsupported signer type")
	ErrSignatureFailed   = errors.New("signature generation failed")
)

// SignerConfig 签名器配置
type SignerConfig struct {
	ClientID   string        // 应用客户端 ID
	PrivateKey crypto.Signer // 私钥
	Algorithm  string        // 签名算法 (RS256, ES256 等)
	KeyID      string        // 证书 ID（用于 kid）
}

// Signer 请求签名器
type Signer struct {
	config SignerConfig
}

// SignResult 签名结果
type SignResult struct {
	Signature string // 完整签名值: {algorithm}.{kid}.{signature_base64}
	Timestamp int64  // 时间戳
	Nonce     string // 随机字符串
	ClientID  string // 客户端 ID
}

// NewSigner 创建签名器
func NewSigner(cfg SignerConfig) (*Signer, error) {
	if cfg.PrivateKey == nil {
		return nil, ErrNilPrivateKey
	}
	if cfg.ClientID == "" {
		return nil, errors.New("client ID is required")
	}
	if cfg.Algorithm == "" {
		return nil, errors.New("algorithm is required")
	}
	if !IsAllowedAlgorithm(cfg.Algorithm) {
		return nil, fmt.Errorf("unsupported algorithm: %s", cfg.Algorithm)
	}

	return &Signer{config: cfg}, nil
}

// SignRequest 签名 HTTP 请求（自动设置 Header）
func (s *Signer) SignRequest(req *http.Request) error {
	// 读取请求体
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		// 重新设置请求体
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// 生成签名
	result, err := s.Sign(req.Method, req.URL.Path, body)
	if err != nil {
		return err
	}

	// 设置请求头
	req.Header.Set(HeaderClientID, result.ClientID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(result.Timestamp, 10))
	req.Header.Set(HeaderNonce, result.Nonce)
	req.Header.Set(HeaderSignature, result.Signature)

	return nil
}

// Sign 生成签名
func (s *Signer) Sign(method, path string, body []byte) (*SignResult, error) {
	timestamp := time.Now().Unix()
	nonce := generateNonce()

	// 构建规范化请求
	canonical := BuildCanonicalRequest(
		s.config.ClientID,
		timestamp,
		nonce,
		method,
		path,
		body,
	)

	// 计算签名
	signatureBytes, err := s.signData(canonical.Hash())
	if err != nil {
		return nil, err
	}

	// 构建签名值: {algorithm}.{kid}.{signature_base64}
	signatureStr := fmt.Sprintf("%s.%s.%s",
		s.config.Algorithm,
		s.config.KeyID,
		base64.RawURLEncoding.EncodeToString(signatureBytes),
	)

	return &SignResult{
		Signature: signatureStr,
		Timestamp: timestamp,
		Nonce:     nonce,
		ClientID:  s.config.ClientID,
	}, nil
}

// signData 使用私钥签名数据
func (s *Signer) signData(data []byte) ([]byte, error) {
	hashFunc := getHashFunc(s.config.Algorithm)

	switch key := s.config.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, hashFunc, data)

	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, data)

	default:
		return nil, ErrUnsupportedSigner
	}
}

// getHashFunc 根据算法获取哈希函数
func getHashFunc(algorithm string) crypto.Hash {
	switch algorithm {
	case AlgorithmRS256, AlgorithmES256:
		return crypto.SHA256
	case AlgorithmRS384, AlgorithmES384:
		return crypto.SHA384
	case AlgorithmRS512, AlgorithmES512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// generateNonce 生成随机 Nonce
func generateNonce() string {
	b := make([]byte, NonceLength/2)
	if _, err := rand.Read(b); err != nil {
		// 降级方案：使用时间戳
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// GetClientID 获取客户端 ID
func (s *Signer) GetClientID() string {
	return s.config.ClientID
}

// GetAlgorithm 获取签名算法
func (s *Signer) GetAlgorithm() string {
	return s.config.Algorithm
}

// GetKeyID 获取证书 ID
func (s *Signer) GetKeyID() string {
	return s.config.KeyID
}
