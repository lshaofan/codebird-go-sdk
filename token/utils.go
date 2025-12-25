package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// IsExpiredError 判断错误是否由 Token 过期导致
func IsExpiredError(err error) bool {
	var validationErr *jwt.ValidationError
	if errors.As(err, &validationErr) {
		return validationErr.Errors&jwt.ValidationErrorExpired != 0
	}
	return false
}

// IsSignatureInvalidError 判断错误是否由签名无效导致
func IsSignatureInvalidError(err error) bool {
	var validationErr *jwt.ValidationError
	if errors.As(err, &validationErr) {
		return validationErr.Errors&jwt.ValidationErrorSignatureInvalid != 0
	}
	return false
}

// GetTokenExpireTime 获取令牌剩余过期秒数（不验证签名）
// 返回值：剩余秒数，如果已过期返回 0
func GetTokenExpireTime(tokenString string) (int64, error) {
	claims, err := ExtractClaimsUnverified(tokenString)
	if err != nil {
		return 0, err
	}

	if claims.ExpiresAt == nil {
		return 0, errors.New("token has no expiration")
	}

	remaining := claims.ExpiresAt.Unix() - time.Now().Unix()
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

// ExtractClaimsUnverified 解析令牌但不验证签名（用于读取元信息）
// 注意：此函数不验证签名，仅用于提取 Claims 信息
func ExtractClaimsUnverified(tokenString string) (*Claims, error) {
	parser := jwt.NewParser()
	claims := &Claims{}

	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
