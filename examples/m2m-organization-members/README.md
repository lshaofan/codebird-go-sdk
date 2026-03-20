# m2m organization members example

先设置环境变量：

```bash
export CODEBIRD_ENDPOINT=https://auth.codebird.cloud
export CODEBIRD_CLIENT_ID=YOUR_CLIENT_ID
export CODEBIRD_CLIENT_SECRET=YOUR_CLIENT_SECRET
```

如果你只调组织成员管理接口，不需要设置 `CODEBIRD_RESOURCE`。
只有在你明确要申请组织级 API resource token 时，才额外设置它。

常用命令：

```bash
go run ./examples/m2m-organization-members list <organization-id>
go run ./examples/m2m-organization-members roles <organization-id> <user-id>
```
