# codebird-go-sdk

`codebird-go-sdk` 是码鸟云的官方 Go SDK，当前提供两条能力线：

- `Verifier`：验证 React SPA 或其他前端带来的用户 `access_token`
- `M2MClient`：用 `client_credentials` 调用码鸟云的组织成员管理接口

## 安装

```bash
go get github.com/lshaofan/codebird-go-sdk@latest
```

## Verifier 用法

```go
package main

import (
	"context"
	"log"

	codebird "github.com/lshaofan/codebird-go-sdk"
)

func main() {
	verifier, err := codebird.NewVerifier(codebird.Config{
		Issuer:   "https://auth.codebird.cloud",
		Audience: "https://api.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	auth, err := verifier.VerifyAccessToken(context.Background(), "ACCESS_TOKEN")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("user=%s organization=%s admin=%t", auth.Subject, auth.OrganizationID, auth.OrganizationIsAdmin)
}
```

Verifier 当前支持：

- Bearer Token 解析
- OIDC discovery / JWKS 拉取
- JWT 验签
- `iss` / `aud` / `exp` / `nbf` 校验
- 组织 claims 解析
- `organization_roles` 数组与 map 两种格式兼容

## M2M 组织成员管理

```go
package main

import (
	"context"
	"log"

	codebird "github.com/lshaofan/codebird-go-sdk"
)

func main() {
	client, err := codebird.NewM2MClient(codebird.M2MConfig{
		Endpoint:     "https://auth.codebird.cloud",
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Resource:     "urn:codebird:management-api:YOUR_TENANT_ID",
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.ListOrganizationMembers(context.Background(), "org_123", codebird.ListOrganizationMembersInput{
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("members=%d", len(result.Data))
}
```

当前首批支持的组织成员管理接口：

- `ListOrganizationMembers`
- `AddOrganizationMember`
- `RemoveOrganizationMember`
- `GetOrganizationMemberRoles`
- `UpdateOrganizationMemberRoles`

推荐接法：

1. 前端使用 `@codebird/react` 登录
2. 业务后端先验证当前登录用户 token
3. 业务后端自己判断当前用户是否有管理当前组织的权限
4. 通过后，再用 `M2MClient` 调码鸟云组织成员管理接口

这意味着：

- React SDK 负责用户登录与前端上下文
- Go `Verifier` 负责用户 token 验证
- Go `M2MClient` 负责服务端管理接口调用

## 示例

- [examples/verifier/main.go](./examples/verifier/main.go)
- [examples/m2m-organization-members/main.go](./examples/m2m-organization-members/main.go)

## 发布

`codebird-go-sdk` 的发布方式是：

- 在仓库中提交版本变更
- 推送新的语义化 tag，例如 `v0.1.0`
- Go 用户通过：

```bash
go get github.com/lshaofan/codebird-go-sdk@v0.1.0
```

GitHub Actions 会在 tag 推送时运行测试并创建 GitHub Release。
