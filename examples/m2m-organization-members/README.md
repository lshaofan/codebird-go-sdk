# m2m organization members example

先设置环境变量：

```bash
export CODEBIRD_ENDPOINT=https://auth.codebird.cloud
export CODEBIRD_CLIENT_ID=YOUR_CLIENT_ID
export CODEBIRD_CLIENT_SECRET=YOUR_CLIENT_SECRET
export CODEBIRD_RESOURCE=urn:codebird:management-api:YOUR_TENANT_ID
```

常用命令：

```bash
go run ./examples/m2m-organization-members list <organization-id>
go run ./examples/m2m-organization-members roles <organization-id> <user-id>
```
