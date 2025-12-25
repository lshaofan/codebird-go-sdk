package signature

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// CanonicalRequest 规范化请求结构
type CanonicalRequest struct {
	ClientID  string
	Timestamp int64
	Nonce     string
	Method    string
	Path      string
	BodyHash  string
}

// BuildCanonicalRequest 从 HTTP 请求构建规范化请求
func BuildCanonicalRequest(clientID string, timestamp int64, nonce, method, path string, body []byte) *CanonicalRequest {
	return &CanonicalRequest{
		ClientID:  clientID,
		Timestamp: timestamp,
		Nonce:     nonce,
		Method:    strings.ToUpper(method),
		Path:      normalizePath(path),
		BodyHash:  hashBody(body),
	}
}

// BuildCanonicalRequestFromHTTP 从 HTTP 请求对象构建规范化请求
func BuildCanonicalRequestFromHTTP(req *http.Request, body []byte) (*CanonicalRequest, error) {
	clientID := req.Header.Get(HeaderClientID)
	if clientID == "" {
		return nil, fmt.Errorf("missing %s header", HeaderClientID)
	}

	timestampStr := req.Header.Get(HeaderTimestamp)
	if timestampStr == "" {
		return nil, fmt.Errorf("missing %s header", HeaderTimestamp)
	}
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s header: %w", HeaderTimestamp, err)
	}

	nonce := req.Header.Get(HeaderNonce)
	if nonce == "" {
		return nil, fmt.Errorf("missing %s header", HeaderNonce)
	}

	return BuildCanonicalRequest(
		clientID,
		timestamp,
		nonce,
		req.Method,
		req.URL.Path,
		body,
	), nil
}

// String 生成规范化请求字符串（用于签名）
func (cr *CanonicalRequest) String() string {
	return fmt.Sprintf(
		"client_id=%s\ntimestamp=%d\nnonce=%s\nmethod=%s\npath=%s\nbody_hash=%s",
		cr.ClientID,
		cr.Timestamp,
		cr.Nonce,
		cr.Method,
		cr.Path,
		cr.BodyHash,
	)
}

// Hash 计算规范化请求的 SHA256 哈希
func (cr *CanonicalRequest) Hash() []byte {
	hash := sha256.Sum256([]byte(cr.String()))
	return hash[:]
}

// HashHex 计算规范化请求的 SHA256 哈希（十六进制字符串）
func (cr *CanonicalRequest) HashHex() string {
	return hex.EncodeToString(cr.Hash())
}

// normalizePath 规范化路径
func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	// 确保以 / 开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// 移除尾部的 /（除非是根路径）
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

// hashBody 计算请求体的 SHA256 哈希
func hashBody(body []byte) string {
	if len(body) == 0 {
		// 空 body 的标准哈希值
		hash := sha256.Sum256([]byte{})
		return hex.EncodeToString(hash[:])
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}
