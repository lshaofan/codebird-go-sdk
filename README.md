# codebird-go-sdk
码鸟认证中心 Go SDK，用于第三方服务对接码鸟云认证中心：登录/刷新令牌、OAuth2 授权码登录、用户信息管理、离线验签（JWKS）。

## 环境要求

- Go 版本：1.23.6

## 功能概览

- `client`：调用认证中心 OpenAPI 接口
  - 账号密码登录（AccountLogin）
  - OAuth2 授权码登录（CodeLogin）
  - 刷新令牌（RefreshToken）
  - 获取用户信息（GetUserInfo）
  - 更新用户信息（UpdateUserInfo）
  - 用户注册（Register）
  - 登出（Logout）
- `token`：
  - `token.Manager`：JWT 解析与校验（支持 access/refresh、kid、证书签名算法）。
  - `token.NewHTTPJWKSProvider`：从认证中心 `/api/v1/openapi/auth/jwks` 拉取公钥证书并缓存，供离线验签使用。

## 安装

如果你通过 Go Module 依赖该 SDK：

```bash
go get github.com/lshaofan/codebird-go-sdk
```

如果你在本地开发环境中通过 `replace` 引入，请在你的项目 `go.mod` 中配置本地路径。

## 认证中心接口约定

SDK 默认按以下路径调用认证中心 OpenAPI（可通过 `client.WithAuthPrefix` 修改，默认前缀为 `/api/v1/openapi/auth`）：

| 接口 | 方法 | 路径 | 说明 |
|------|------|------|------|
| JWKS 公钥 | GET | `/api/v1/openapi/auth/jwks` | 获取公钥证书用于离线验签 |
| 账号密码登录 | POST | `/api/v1/openapi/auth/account_login` | 账号密码登录 |
| 授权码登录 | POST | `/api/v1/openapi/auth/code_login` | OAuth2 授权码换取令牌 |
| 刷新令牌 | POST | `/api/v1/openapi/auth/refresh_token` | 刷新访问令牌 |
| 获取用户信息 | GET | `/api/v1/openapi/auth/userinfo` | 获取当前用户信息（需 Bearer Token） |
| 更新用户信息 | POST | `/api/v1/openapi/auth/userinfo` | 更新当前用户信息（需 Bearer Token） |
| 用户注册 | POST | `/api/v1/openapi/auth/register` | 用户注册 |
| 登出 | POST | `/api/v1/openapi/auth/logout` | 登出（需 Bearer Token） |

其中：

- `account_login` 的请求体包含 `client` 与 `account_params`（账号、密码、组织编码、应用 ClientID）。
- `code_login` 的请求体包含 `client_id`、`code`、`state`、`secret`。
- `refresh_token` 的请求体包含 `client` 与 `refresh_token`。
- JWKS 响应使用 `kid=证书ID`，并携带 `x5c`（Base64 DER 证书），SDK 的 HTTP Provider 将优先使用 `x5c` 做验签。

## 快速开始

### 1) 账号密码登录 + 刷新令牌

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	cli := client.New("http://localhost:8080")

	loginRes, err := cli.AccountLogin(context.Background(), client.AccountLoginRequest{
		Account:          "admin",
		Password:         "password",
		OrganizationCode: "default",
		ClientID:         "default",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("access:", loginRes.AccessToken)

	refreshRes, err := cli.RefreshToken(context.Background(), client.RefreshTokenRequest{
		RefreshToken: loginRes.RefreshToken,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("new access:", refreshRes.AccessToken)
}
```

### 2) OAuth2 授权码登录

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	cli := client.New("http://localhost:8080")

	// 使用授权码换取访问令牌
	tokenPair, err := cli.CodeLogin(context.Background(), client.CodeLoginRequest{
		ClientID: 1,                    // 应用客户端 ID
		Code:     "authorization_code", // 从回调获取的授权码
		State:    "random_state",       // 状态参数
		Secret:   "client_secret",      // 客户端密钥
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("access:", tokenPair.AccessToken)
	fmt.Println("refresh:", tokenPair.RefreshToken)
}
```

### 3) 用户信息管理

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	cli := client.New("http://localhost:8080")
	accessToken := "YOUR_ACCESS_TOKEN"

	// 获取用户信息
	userInfo, err := cli.GetUserInfo(context.Background(), accessToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("user:", userInfo.Username)
	fmt.Println("nickname:", userInfo.Nickname)

	// 更新用户信息
	nickname := "新昵称"
	updatedInfo, err := cli.UpdateUserInfo(context.Background(), accessToken, client.UpdateUserInfoRequest{
		Nickname: &nickname,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("updated nickname:", updatedInfo.Nickname)
}
```

### 4) 用户注册

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	cli := client.New("http://localhost:8080")

	resp, err := cli.Register(context.Background(), client.RegisterRequest{
		Username:         "newuser",
		Password:         "password123",
		OrganizationCode: "default",
		ClientID:         "default",
		Email:            "user@example.com",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("registered user id:", resp.ID)
}
```

### 5) 登出

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	cli := client.New("http://localhost:8080")

	accessToken := "YOUR_ACCESS_TOKEN"
	refreshToken := "YOUR_REFRESH_TOKEN"

	err := cli.Logout(context.Background(), accessToken, refreshToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("logout success")
}
```

### 6) 通过 JWKS 离线验签（推荐）

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/lshaofan/codebird-go-sdk/token"
)

func main() {
	provider := token.NewHTTPJWKSProvider(
		"http://localhost:8080/api/v1/auth/jwks",
		token.WithJWKSCacheTTL(5*time.Minute),
	)
	manager := token.NewManager(token.WithCertificateProvider(provider))

	claims, err := manager.ValidateToken(context.Background(), "YOUR_JWT")
	if err != nil {
		if token.IsExpiredError(err) {
			panic("token 已过期")
		}
		if token.IsSignatureInvalidError(err) {
			panic("token 签名无效")
		}
		panic(err)
	}

	fmt.Println("user_id:", claims.User.ID)
	fmt.Println("org_code:", claims.OrganizationCode)
	fmt.Println("app_client_id:", claims.ApplicationClient)
}
```

## 常用模式

### 从 HTTP Header 提取 Bearer Token

```go
package auth

import (
	"errors"
	"strings"
)

func ExtractBearerToken(authorization string) (string, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", errors.New("缺少 Authorization")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) {
		return "", errors.New("Authorization 格式错误")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	if token == "" {
		return "", errors.New("缺少 Token")
	}
	return token, nil
}
```

### 常见错误判断

- `token.IsExpiredError(err)`：JWT 过期。
- `token.IsSignatureInvalidError(err)`：签名无效。
- 其它错误通常意味着证书不存在、证书不合法或算法不支持（例如 `token.ErrCertificateNotConfigured`、`token.ErrInvalidCertificate` 等）。

## 示例代码

- 登录/刷新：`examples/login_refresh/main.go`
- 离线验签：`examples/validate_jwt/main.go`

## 功能范围

- `token`：JWT 生成与校验（支持 access/refresh、kid、证书签名）。
- `token.NewHTTPJWKSProvider`：通过认证中心 `/api/v1/openapi/auth/jwks` 拉取公钥并缓存，用于离线验签。
- `client`：完整的认证中心 HTTP Client 封装，包括：
  - 账号密码登录 / OAuth2 授权码登录 / 刷新令牌
  - 用户信息获取与更新
  - 用户注册 / 登出

## 使用示例

### 1. 通过 JWKS 离线验签

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/token"
)

func main() {
	provider := token.NewHTTPJWKSProvider("http://localhost:8080/api/v1/auth/jwks")
	manager := token.NewManager(token.WithCertificateProvider(provider))

	claims, err := manager.ValidateToken(context.Background(), "YOUR_JWT")
	if err != nil {
		panic(err)
	}
	fmt.Println(claims.User.ID, claims.OrganizationCode, claims.ApplicationClient)
}
```

### 2. 账号密码登录 + 刷新令牌

```go
package main

import (
	"context"
	"fmt"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	cli := client.New("http://localhost:8080")

	loginRes, err := cli.AccountLogin(context.Background(), client.AccountLoginRequest{
		Account:          "admin",
		Password:         "password",
		OrganizationCode: "default",
		ClientID:         "default",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("access:", loginRes.AccessToken)

	refreshRes, err := cli.RefreshToken(context.Background(), client.RefreshTokenRequest{
		RefreshToken: loginRes.RefreshToken,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("new access:", refreshRes.AccessToken)
}
```
