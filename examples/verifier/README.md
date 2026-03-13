# verifier example

```bash
go run ./examples/verifier
```

然后带上 Bearer Token 访问：

```bash
curl http://localhost:8081/profile \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```
