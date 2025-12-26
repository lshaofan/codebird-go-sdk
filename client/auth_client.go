package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/lshaofan/codebird-go-sdk/signature"
)

// Client 认证中心 HTTP 客户端
type Client struct {
	oauth2Config *OAuth2Config
	baseURL      string
	httpClient   *http.Client
	authPrefix   string
	signer       *signature.Signer // 应用签名器（用于服务器间认证）
}

// Option 配置项
type Option func(*Client)

// WithHTTPClient 自定义 HTTP 客户端
func WithHTTPClient(c *http.Client) Option {
	return func(cli *Client) {
		cli.httpClient = c
	}
}

// WithAuthPrefix 自定义认证路径前缀（默认 /api/v1/openapi/auth）
func WithAuthPrefix(prefix string) Option {
	return func(cli *Client) {
		cli.authPrefix = "/" + strings.Trim(prefix, "/")
	}
}

// WithAppSignature 配置应用签名认证（用于服务器间通信）
// 配置后，调用 GetUserInfoByID 等方法会自动签名请求
func WithAppSignature(cfg signature.SignerConfig) Option {
	return func(cli *Client) {
		signer, err := signature.NewSigner(cfg)
		if err != nil {
			// 记录错误但不中断，调用时会检查
			return
		}
		cli.signer = signer
	}
}

// WithAppSignatureFromPEM 从 PEM 字符串配置应用签名（简化版）
// clientID: 应用客户端 ID
// certID: 证书 ID（数据库中的证书记录 ID，uint 类型）
// privateKeyPEM: PEM 格式的私钥字符串
func WithAppSignatureFromPEM(clientID string, certID uint, privateKeyPEM string) Option {
	return func(cli *Client) {
		privateKey, alg, err := signature.LoadPrivateKey([]byte(privateKeyPEM))
		if err != nil {
			return
		}
		signer, err := signature.NewSigner(signature.SignerConfig{
			ClientID:   clientID,
			PrivateKey: privateKey,
			Algorithm:  alg,
			KeyID:      fmt.Sprintf("%d", certID),
		})
		if err != nil {
			return
		}
		cli.signer = signer
	}
}

// WithAppSignatureFromFile 从文件配置应用签名（简化版）
// clientID: 应用客户端 ID
// certID: 证书 ID（数据库中的证书记录 ID，uint 类型）
// privateKeyPath: 私钥文件路径
func WithAppSignatureFromFile(clientID string, certID uint, privateKeyPath string) Option {
	return func(cli *Client) {
		privateKey, alg, err := signature.LoadPrivateKeyFromFile(privateKeyPath)
		if err != nil {
			return
		}
		signer, err := signature.NewSigner(signature.SignerConfig{
			ClientID:   clientID,
			PrivateKey: privateKey,
			Algorithm:  alg,
			KeyID:      fmt.Sprintf("%d", certID),
		})
		if err != nil {
			return
		}
		cli.signer = signer
	}
}

// New 创建客户端
func New(baseURL string, opts ...Option) *Client {
	cli := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
		authPrefix: "/api/v1/openapi/auth",
	}
	for _, opt := range opts {
		opt(cli)
	}
	return cli
}

// AccountLoginRequest 账号密码登录请求
type AccountLoginRequest struct {
	Account          string
	Password         string
	OrganizationCode string
	ClientID         string
	Client           string // 可选，默认 admin
}

// RefreshTokenRequest 刷新令牌请求
type RefreshTokenRequest struct {
	RefreshToken string
	Client       string // 可选，默认 admin
}

// TokenPair 为认证中心登录/刷新接口返回结构
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiredAt    time.Time `json:"expired_at"`
}

// AccountLogin 账号密码登录
func (c *Client) AccountLogin(ctx context.Context, req AccountLoginRequest) (*TokenPair, error) {
	clientVal := strings.TrimSpace(req.Client)
	if clientVal == "" {
		clientVal = "admin"
	}

	payload := map[string]interface{}{
		"client": clientVal,
		"account_params": map[string]interface{}{
			"account":           req.Account,
			"password":          req.Password,
			"organization_code": req.OrganizationCode,
			"client_id":         req.ClientID,
		},
	}

	return c.postToken(ctx, "/account_login", payload)
}

// RefreshToken 刷新访问令牌
func (c *Client) RefreshToken(ctx context.Context, req RefreshTokenRequest) (*TokenPair, error) {
	clientVal := strings.TrimSpace(req.Client)
	if clientVal == "" {
		clientVal = "admin"
	}

	payload := map[string]interface{}{
		"client":        clientVal,
		"refresh_token": req.RefreshToken,
	}

	return c.postToken(ctx, "/refresh_token", payload)
}

func (c *Client) postToken(ctx context.Context, path string, payload interface{}) (*TokenPair, error) {
	url := c.baseURL + c.authPrefix + path
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 非 200 状态码时，尝试解析错误响应体
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var result defaultResult[TokenPair]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Code != 0 {
		msg := result.Message
		if msg == "" {
			msg = result.Msg
		}
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("code %d: %s", result.Code, msg)
	}

	// 优先使用 Result 字段（go-framework 格式），否则使用 Data 字段
	data := result.Result
	if data.AccessToken == "" && result.Data.AccessToken != "" {
		data = result.Data
	}
	return &data, nil
}

type defaultResult[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Result  T      `json:"result"` // go-framework Response 使用 result 字段
	Data    T      `json:"data"`   // 兼容其他系统使用 data 字段
}

// errorResult 用于解析错误响应
type errorResult struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Msg     string `json:"msg,omitempty"`
}

// parseErrorResponse 解析错误响应体，提取错误信息
func parseErrorResponse(resp *http.Response) error {
	// 尝试读取响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request failed with status %s", resp.Status)
	}

	// 尝试解析为 JSON 错误格式
	var errResult errorResult
	if err := json.Unmarshal(bodyBytes, &errResult); err != nil {
		// 无法解析为 JSON，返回原始状态码错误
		return fmt.Errorf("request failed with status %s", resp.Status)
	}

	// 获取错误消息
	msg := errResult.Message
	if msg == "" {
		msg = errResult.Msg
	}
	if msg == "" {
		return fmt.Errorf("request failed with status %s", resp.Status)
	}

	// 返回包含错误码和消息的错误
	if errResult.Code != 0 {
		return fmt.Errorf("code %d: %s", errResult.Code, msg)
	}
	return fmt.Errorf("%s", msg)
}

// SetHTTPTimeout 快捷设置超时时间
func (c *Client) SetHTTPTimeout(d time.Duration) {
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	c.httpClient.Timeout = d
}

// ==================== OAuth2 授权码登录 ====================

// CodeLoginRequest 授权码登录请求
type CodeLoginRequest struct {
	ClientID string // 应用客户端 ID（必填）
	Code     string // 授权码（必填）
	State    string // 状态参数（必填）
	Secret   string // 客户端密钥（必填）
}

// CodeLogin 使用授权码换取访问令牌
func (c *Client) CodeLogin(ctx context.Context, req CodeLoginRequest) (*TokenPair, error) {
	payload := map[string]interface{}{
		"client_id": req.ClientID,
		"code":      req.Code,
		"state":     req.State,
		"secret":    req.Secret,
	}

	return c.postToken(ctx, "/code_login", payload)
}

// ==================== 用户信息接口 ====================

// UserInfo 用户信息
type UserInfo struct {
	ID            uint                   `json:"id"`
	Username      string                 `json:"username"`
	Nickname      string                 `json:"nickname"`
	Avatar        string                 `json:"avatar"`
	Email         string                 `json:"email"`
	Phone         string                 `json:"phone"`
	IsSuper       bool                   `json:"is_super"`
	Introduction  string                 `json:"introduction"`
	Gender        uint                   `json:"gender"`
	Organizations []UserOrganizationInfo `json:"organizations"`
}

// UserOrganizationInfo 用户组织信息
type UserOrganizationInfo struct {
	OrganizationID   uint   `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	OrganizationCode string `json:"organization_code"`
	OrganizationLogo string `json:"organization_logo"`
	Role             string `json:"role"`
	IsDefault        bool   `json:"is_default"`
}

// GetUserInfo 获取当前用户信息
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	return getWithAuth[UserInfo](c, ctx, "/userinfo", accessToken)
}

// UpdateUserInfoRequest 更新用户信息请求
type UpdateUserInfoRequest struct {
	Nickname     *string `json:"nickname,omitempty"`     // 昵称
	Avatar       *string `json:"avatar,omitempty"`       // 头像URL
	Email        *string `json:"email,omitempty"`        // 邮箱
	Phone        *string `json:"phone,omitempty"`        // 手机号
	Gender       *uint   `json:"gender,omitempty"`       // 性别（0=未知、1=男、2=女）
	Introduction *string `json:"introduction,omitempty"` // 简介
	OldPassword  *string `json:"old_password,omitempty"` // 旧密码（修改密码时必填）
	NewPassword  *string `json:"new_password,omitempty"` // 新密码（修改密码时必填）
}

// UpdateUserInfo 更新当前用户信息
func (c *Client) UpdateUserInfo(ctx context.Context, accessToken string, req UpdateUserInfoRequest) (*UserInfo, error) {
	return postWithAuth[UserInfo](c, ctx, "/userinfo", accessToken, req)
}

// ==================== 应用签名认证接口 ====================

// UserInfoByIDOrganization 用户当前组织信息（应用签名认证）
type UserInfoByIDOrganization struct {
	OrganizationID   uint   `json:"organization_id"`   // 组织ID
	OrganizationName string `json:"organization_name"` // 组织名称
	OrganizationCode string `json:"organization_code"` // 组织编码
	OrganizationLogo string `json:"organization_logo"` // 组织Logo
	Role             string `json:"role"`              // 用户在组织中的角色（owner/admin/member）
}

// UserInfoByID 通过用户 ID 获取的用户信息（应用签名认证）
type UserInfoByID struct {
	ID           uint                      `json:"id"`
	Username     string                    `json:"username"`
	Nickname     string                    `json:"nickname"`
	Avatar       string                    `json:"avatar"`
	Email        string                    `json:"email"`
	Phone        string                    `json:"phone"`
	Gender       int                       `json:"gender"`
	Introduction string                    `json:"introduction"`
	IsSuper      bool                      `json:"is_super"`
	Status       int                       `json:"status"`
	Roles        []string                  `json:"roles,omitempty"`
	Organization *UserInfoByIDOrganization `json:"organization,omitempty"` // 当前组织信息
}

// GetUserInfoByID 通过用户 ID 获取用户信息（需要配置应用签名）
// 使用应用签名认证，适用于服务器间通信
// 需要先通过 WithAppSignature 配置签名器
func (c *Client) GetUserInfoByID(ctx context.Context, userID uint) (*UserInfoByID, error) {
	if c.signer == nil {
		return nil, fmt.Errorf("app signature not configured, use WithAppSignature option")
	}

	payload := map[string]interface{}{
		"user_id": userID,
	}

	return postWithAppSign[UserInfoByID](c, ctx, "/userinfo", payload)
}

// postWithAppSign 发送带应用签名的 POST 请求
func postWithAppSign[T any](c *Client, ctx context.Context, path string, payload interface{}) (*T, error) {
	if c.signer == nil {
		return nil, fmt.Errorf("app signature not configured")
	}

	url := c.baseURL + c.authPrefix + path
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// 使用签名器签名请求
	if err := c.signer.SignRequest(req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return doRequest[T](c, req)
}

// ==================== 用户注册 ====================

// RegisterRequest 用户注册请求
type RegisterRequest struct {
	Username         string `json:"username"`           // 用户名（必填）
	Password         string `json:"password"`           // 密码（必填）
	OrganizationCode string `json:"organization_code"`  // 组织编码（必填）
	ClientID         string `json:"client_id"`          // 应用客户端ID（必填）
	Email            string `json:"email,omitempty"`    // 邮箱（可选）
	Phone            string `json:"phone,omitempty"`    // 手机号（可选）
	Nickname         string `json:"nickname,omitempty"` // 昵称（可选）
}

// RegisterResponse 用户注册响应
type RegisterResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Status   uint   `json:"status"`
}

// Register 用户注册
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	return post[RegisterResponse](c, ctx, "/register", req)
}

// ==================== 登出 ====================

// LogoutRequest 登出请求
type LogoutRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Logout 登出（将 Token 加入黑名单）
func (c *Client) Logout(ctx context.Context, accessToken, refreshToken string) error {
	payload := LogoutRequest{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	_, err := postWithAuth[struct{}](c, ctx, "/logout", accessToken, payload)
	return err
}

// ==================== 通用请求方法 ====================

// post 发送 POST 请求（无需认证）
func post[T any](c *Client, ctx context.Context, path string, payload interface{}) (*T, error) {
	url := c.baseURL + c.authPrefix + path
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return doRequest[T](c, req)
}

// postWithAuth 发送带认证的 POST 请求
func postWithAuth[T any](c *Client, ctx context.Context, path string, accessToken string, payload interface{}) (*T, error) {
	url := c.baseURL + c.authPrefix + path
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return doRequest[T](c, req)
}

// getWithAuth 发送带认证的 GET 请求
func getWithAuth[T any](c *Client, ctx context.Context, path string, accessToken string) (*T, error) {
	url := c.baseURL + c.authPrefix + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return doRequest[T](c, req)
}

// doRequest 执行请求并解析响应
func doRequest[T any](c *Client, req *http.Request) (*T, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 非 200 状态码时，尝试解析错误响应体
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var result defaultResult[T]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Code != 0 {
		msg := result.Message
		if msg == "" {
			msg = result.Msg
		}
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("code %d: %s", result.Code, msg)
	}

	// 优先使用 Result 字段（go-framework 格式），否则使用 Data 字段
	data := result.Result
	if reflect.ValueOf(data).IsZero() && !reflect.ValueOf(result.Data).IsZero() {
		data = result.Data
	}
	return &data, nil
}

// ==================== OAuth2 授权 URL 生成 ====================

// OAuth2Config OAuth2 配置
type OAuth2Config struct {
	BasePath         string // OAuth2 授权页面路径前缀，如 /view/code_bird_cloud/admin
	ClientID         string // 应用客户端 ID
	OrganizationCode string // 组织编码
}

// WithOAuth2Config 配置 OAuth2 参数
func WithOAuth2Config(cfg OAuth2Config) Option {
	return func(cli *Client) {
		cli.oauth2Config = &cfg
	}
}

// GetAuthorizeURL 构建 OAuth2 授权地址
// redirectURI: 回调地址
// state: 状态参数（用于 CSRF 防护）
// scope: 授权范围（可选，默认 "openid profile"）
func (c *Client) GetAuthorizeURL(redirectURI, state, scope string) string {
	if c.oauth2Config == nil {
		return ""
	}

	if scope == "" {
		scope = "openid profile"
	}

	basePath := strings.TrimRight(c.oauth2Config.BasePath, "/")

	params := fmt.Sprintf(
		"client_id=%s&organization_code=%s&response_type=code&scope=%s&redirect_uri=%s&state=%s",
		c.oauth2Config.ClientID,
		c.oauth2Config.OrganizationCode,
		scope,
		redirectURI,
		state,
	)

	return fmt.Sprintf("%s%s/oauth/authorize?%s", c.baseURL, basePath, params)
}

// GetAuthorizeURLTemplate 构建 OAuth2 授权地址模板（不含 redirect_uri 值）
// 返回的 URL 以 &redirect_uri= 结尾，调用方需追加实际的回调地址
func (c *Client) GetAuthorizeURLTemplate() string {
	if c.oauth2Config == nil {
		return ""
	}

	basePath := strings.TrimRight(c.oauth2Config.BasePath, "/")

	params := fmt.Sprintf(
		"client_id=%s&organization_code=%s&response_type=code&scope=openid+profile&redirect_uri=",
		c.oauth2Config.ClientID,
		c.oauth2Config.OrganizationCode,
	)

	return fmt.Sprintf("%s%s/oauth/authorize?%s", c.baseURL, basePath, params)
}
