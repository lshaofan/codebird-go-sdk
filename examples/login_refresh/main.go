package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lshaofan/codebird-go-sdk/client"
)

func main() {
	baseURL := os.Getenv("CODEBIRD_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	account := os.Getenv("CODEBIRD_ACCOUNT")
	password := os.Getenv("CODEBIRD_PASSWORD")
	orgCode := os.Getenv("CODEBIRD_ORG_CODE")
	clientID := os.Getenv("CODEBIRD_CLIENT_ID")

	if account == "" || password == "" || orgCode == "" || clientID == "" {
		panic("请设置环境变量：CODEBIRD_ACCOUNT/CODEBIRD_PASSWORD/CODEBIRD_ORG_CODE/CODEBIRD_CLIENT_ID")
	}

	cli := client.New(baseURL)

	loginRes, err := cli.AccountLogin(context.Background(), client.AccountLoginRequest{
		Account:          account,
		Password:         password,
		OrganizationCode: orgCode,
		ClientID:         clientID,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("access_token:", loginRes.AccessToken)
	fmt.Println("refresh_token:", loginRes.RefreshToken)
	fmt.Println("expired_at:", loginRes.ExpiredAt)

	refreshRes, err := cli.RefreshToken(context.Background(), client.RefreshTokenRequest{
		RefreshToken: loginRes.RefreshToken,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("new_access_token:", refreshRes.AccessToken)
	fmt.Println("new_refresh_token:", refreshRes.RefreshToken)
	fmt.Println("new_expired_at:", refreshRes.ExpiredAt)
}
