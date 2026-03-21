# codebird-go-sdk

`codebird-go-sdk` 是码鸟云的官方 Go SDK，当前提供两条能力线：

- `Verifier`：验证 React SPA 或其他前端带来的用户 `access_token`
- `Client`：基于当前用户 `access_token` 获取实时会话上下文
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

当前组织 claims 标准约定：

- `organization_roles` 使用新版字符串数组格式，例如：

```json
["org_123:admin", "org_456:member"]
```

- 组织管理员身份请始终以 `organization_is_admin` 为准
- 不要根据 `organization_roles` 中是否包含 `admin` 推断组织管理员身份

## 获取实时会话上下文

如果业务后端需要按数据库最新状态拿到用户、应用和组织关系，而不是只依赖 token claims，可以再使用 `Client`：

```go
package main

import (
	"context"
	"log"

	codebird "github.com/lshaofan/codebird-go-sdk"
)

func main() {
	client, err := codebird.NewClient(codebird.Config{
		Issuer: "https://auth.codebird.cloud",
	})
	if err != nil {
		log.Fatal(err)
	}

	sessionCtx, err := client.GetSessionContext(context.Background(), "ACCESS_TOKEN", &codebird.GetSessionContextOptions{
		OrganizationID: "org_123",
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("tenant=%v user=%s app=%v organization=%v", sessionCtx.Tenant, sessionCtx.User.ID, sessionCtx.Application, sessionCtx.Organization)
}
```

推荐分层：

- `Verifier`：验证 token、解析轻量 claims
- `Client.GetSessionContext`：获取实时用户 / 组织 / 应用上下文

实时上下文里还会返回：

- `SessionContext.Tenant`

其中 `Tenant.Slug` 是终端用户租户化入口的标准标识，可用于识别：

- `/t/{tenant.slug}/sign-in`
- `/t/{tenant.slug}/account-center/...`

也就是说：

- claims 适合做轻量登录态上下文
- 实时权限判断应以 `GetSessionContext` 结果为准
- 轻量 claims 中是否为组织管理员，看 `OrganizationIsAdmin`
- 实时上下文中是否为组织管理员，看 `SessionContext.Organization.IsAdmin`

## 构造租户化终端用户入口

如果业务系统需要自己构造认证中心终端用户入口，可以直接使用 `Client` 提供的 URL helper：

```go
signInURL, err := client.BuildTenantSignInURL("tenant-demo")
registerURL, err := client.BuildTenantRegisterURL("tenant-demo")
forgotPasswordURL, err := client.BuildTenantForgotPasswordURL("tenant-demo")
```

对应结果分别是：

- `/t/{tenantSlug}/sign-in`
- `/t/{tenantSlug}/register`
- `/t/{tenantSlug}/forgot-password`

注意：

- `tenantSlug` 不能为空
- 这组 helper 只用于终端用户入口地址构造
- 账户中心仍然应通过后端 SSO 跳转地址进入，不建议手工拼裸 `/account-center/...`

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
		Endpoint:       "https://auth.codebird.cloud",
		ClientID:       "YOUR_CLIENT_ID",
		ClientSecret:   "YOUR_CLIENT_SECRET",
		OrganizationID: "org_123",
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

如果你只是调用组织成员管理接口，推荐只配置：

- `Endpoint`
- `ClientID`
- `ClientSecret`
- `OrganizationID`

此时 SDK 会申请组织级 token，不需要传 `Resource`。

只有在你明确要申请“组织级 API resource token”时，才额外传：

- `Resource`

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
- 推送新的语义化 tag，例如 `v0.2.0`
- Go 用户通过：

```bash
go get github.com/lshaofan/codebird-go-sdk@v0.2.0
```

GitHub Actions 会在 tag 推送时运行测试并创建 GitHub Release。
