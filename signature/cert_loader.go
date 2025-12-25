package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	ErrInvalidPEM        = errors.New("invalid PEM data")
	ErrUnsupportedKey    = errors.New("unsupported key type")
	ErrKeyNotFound       = errors.New("key not found in PEM data")
	ErrInvalidPrivateKey = errors.New("invalid private key")
	ErrInvalidPublicKey  = errors.New("invalid public key")
)

// LoadPrivateKeyFromFile 从文件加载私钥
// 返回: 私钥, 算法, 错误
func LoadPrivateKeyFromFile(path string) (crypto.Signer, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read private key file: %w", err)
	}
	return LoadPrivateKey(data)
}

// LoadPrivateKey 从 PEM 数据加载私钥
// 返回: 私钥, 算法, 错误
func LoadPrivateKey(pemData []byte) (crypto.Signer, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", ErrInvalidPEM
	}

	var privateKey crypto.Signer
	var algorithm string

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		privateKey = key
		algorithm = detectRSAAlgorithm(key)

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse EC private key: %w", err)
		}
		privateKey = key
		algorithm = detectECDSAAlgorithm(key)

	case "PRIVATE KEY":
		// PKCS#8 格式
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			privateKey = k
			algorithm = detectRSAAlgorithm(k)
		case *ecdsa.PrivateKey:
			privateKey = k
			algorithm = detectECDSAAlgorithm(k)
		default:
			return nil, "", ErrUnsupportedKey
		}

	default:
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedKey, block.Type)
	}

	return privateKey, algorithm, nil
}

// LoadPublicKeyFromFile 从文件加载公钥
// 返回: 公钥, 算法, 错误
func LoadPublicKeyFromFile(path string) (crypto.PublicKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read public key file: %w", err)
	}
	return LoadPublicKey(data)
}

// LoadPublicKey 从 PEM 数据加载公钥
// 返回: 公钥, 算法, 错误
func LoadPublicKey(pemData []byte) (crypto.PublicKey, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", ErrInvalidPEM
	}

	var publicKey crypto.PublicKey
	var algorithm string

	switch block.Type {
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		publicKey = key
		algorithm = detectRSAAlgorithmFromPublic(key)

	case "PUBLIC KEY":
		// PKIX 格式
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PublicKey:
			publicKey = k
			algorithm = detectRSAAlgorithmFromPublic(k)
		case *ecdsa.PublicKey:
			publicKey = k
			algorithm = detectECDSAAlgorithmFromPublic(k)
		default:
			return nil, "", ErrUnsupportedKey
		}

	case "CERTIFICATE":
		// X.509 证书
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse certificate: %w", err)
		}
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			publicKey = k
			algorithm = detectRSAAlgorithmFromPublic(k)
		case *ecdsa.PublicKey:
			publicKey = k
			algorithm = detectECDSAAlgorithmFromPublic(k)
		default:
			return nil, "", ErrUnsupportedKey
		}

	default:
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedKey, block.Type)
	}

	return publicKey, algorithm, nil
}

// LoadPublicKeyFromCertificate 从证书 PEM 数据加载公钥
func LoadPublicKeyFromCertificate(pemData []byte) (crypto.PublicKey, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", ErrInvalidPEM
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k, detectRSAAlgorithmFromPublic(k), nil
	case *ecdsa.PublicKey:
		return k, detectECDSAAlgorithmFromPublic(k), nil
	default:
		return nil, "", ErrUnsupportedKey
	}
}

// detectRSAAlgorithm 根据 RSA 私钥检测算法
func detectRSAAlgorithm(key *rsa.PrivateKey) string {
	bitSize := key.N.BitLen()
	switch {
	case bitSize >= 4096:
		return AlgorithmRS512
	case bitSize >= 3072:
		return AlgorithmRS384
	default:
		return AlgorithmRS256
	}
}

// detectRSAAlgorithmFromPublic 根据 RSA 公钥检测算法
func detectRSAAlgorithmFromPublic(key *rsa.PublicKey) string {
	bitSize := key.N.BitLen()
	switch {
	case bitSize >= 4096:
		return AlgorithmRS512
	case bitSize >= 3072:
		return AlgorithmRS384
	default:
		return AlgorithmRS256
	}
}

// detectECDSAAlgorithm 根据 ECDSA 私钥检测算法
func detectECDSAAlgorithm(key *ecdsa.PrivateKey) string {
	bitSize := key.Curve.Params().BitSize
	switch {
	case bitSize >= 512:
		return AlgorithmES512
	case bitSize >= 384:
		return AlgorithmES384
	default:
		return AlgorithmES256
	}
}

// detectECDSAAlgorithmFromPublic 根据 ECDSA 公钥检测算法
func detectECDSAAlgorithmFromPublic(key *ecdsa.PublicKey) string {
	bitSize := key.Curve.Params().BitSize
	switch {
	case bitSize >= 512:
		return AlgorithmES512
	case bitSize >= 384:
		return AlgorithmES384
	default:
		return AlgorithmES256
	}
}

// GetPublicKeyFromSigner 从 Signer 接口获取公钥
func GetPublicKeyFromSigner(signer crypto.Signer) crypto.PublicKey {
	return signer.Public()
}
