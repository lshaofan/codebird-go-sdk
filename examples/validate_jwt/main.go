package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/lshaofan/codebird-go-sdk/token"
)

func main() {
	baseURL := os.Getenv("CODEBIRD_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	jwtToken := os.Getenv("CODEBIRD_JWT")
	if jwtToken == "" {
		panic("请设置环境变量：CODEBIRD_JWT")
	}

	provider := token.NewHTTPJWKSProvider(baseURL+"/api/v1/auth/jwks", token.WithJWKSCacheTTL(5*time.Minute))
	manager := token.NewManager(token.WithCertificateProvider(provider))

	claims, err := manager.ValidateToken(context.Background(), jwtToken)
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
	fmt.Println("org_id:", claims.OrganizationID)
	fmt.Println("org_code:", claims.OrganizationCode)
	fmt.Println("app_id:", claims.ApplicationID)
	fmt.Println("app_client_id:", claims.ApplicationClient)
	fmt.Println("cert_id:", claims.CertificateID)
	fmt.Println("token_kind:", claims.RefreshTokenType)
}
