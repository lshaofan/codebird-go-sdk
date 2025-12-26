# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

码鸟认证中心 Go SDK (codebird-go-sdk) - 用于第三方服务对接码鸟云认证中心，提供登录/刷新令牌、OAuth2 授权码登录、用户信息管理、离线验签（JWKS）等功能。

## Build & Development Commands

```bash
# 安装依赖
go mod tidy

# 构建
go build ./...

# 运行示例（需设置环境变量）
CODEBIRD_BASE_URL=http://localhost:8080 \
CODEBIRD_ACCOUNT=admin \
CODEBIRD_PASSWORD=password \
CODEBIRD_ORG_CODE=default \
CODEBIRD_CLIENT_ID=default \
go run examples/login_refresh/main.go

# JWT 验签示例
CODEBIRD_BASE_URL=http://localhost:8080 \
CODEBIRD_JWT=your_jwt_token \
go run examples/validate_jwt/main.go
```

## Architecture

### Module Structure

```
├── client/          # 认证中心 HTTP Client 封装
├── token/           # JWT 解析、校验、JWKS Provider
├── signature/       # 请求签名与验签
└── examples/        # 使用示例
```

### Core Components

**client** (`client/auth_client.go`)
- `Client` - HTTP 客户端，支持 Option 模式配置
- 功能：AccountLogin、CodeLogin、RefreshToken、GetUserInfo、UpdateUserInfo、Register、Logout
- 支持应用签名：`WithAppSignature`、`WithAppSignatureFromPEM`、`WithAppSignatureFromFile`

**token** (`token/`)
- `Manager` - JWT 生成与校验管理器
- `CertificateProvider` 接口 - 证书提供者抽象
- `NewHTTPJWKSProvider` - 从认证中心 JWKS 端点获取公钥，支持缓存
- `Claims` - JWT 声明结构，包含 User、Organization、Application 等信息

**signature** (`signature/`)
- `Signer` - 请求签名器（RSA/ECDSA）
- `Verifier` - 签名验证器，支持时间戳校验和 Nonce 防重放
- 规范化字符串构建：`BuildCanonicalString`

### Key Interfaces

```go
// 证书提供者接口
type CertificateProvider interface {
    GetByID(ctx context.Context, id string) (*Certificate, error)
}

// 公钥提供者（签名验证）
type PublicKeyProvider func(ctx context.Context, clientID string, keyID string) (*rsa.PublicKey, string, error)
```

### Error Handling

token 包提供错误判断辅助函数：
- `token.IsExpiredError(err)` - JWT 过期
- `token.IsSignatureInvalidError(err)` - 签名无效

## API Endpoints

SDK 默认使用前缀 `/api/v1/openapi/auth`，可通过 `client.WithAuthPrefix` 修改：

| 接口 | 方法 | 路径 |
|------|------|------|
| JWKS 公钥 | GET | `/jwks` |
| 账号密码登录 | POST | `/account_login` |
| 授权码登录 | POST | `/code_login` |
| 刷新令牌 | POST | `/refresh_token` |
| 用户信息 | GET/POST | `/userinfo` |
| 用户注册 | POST | `/register` |
| 登出 | POST | `/logout` |

## Dependencies

- `github.com/golang-jwt/jwt/v4` - JWT 解析与签名
- `github.com/google/uuid` - UUID 生成

## Go Version

Go 1.23.6
