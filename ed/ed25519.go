package ed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrInvalidPrivateKey = errors.New("invalid Ed25519 private key")
	ErrInvalidPublicKey  = errors.New("invalid Ed25519 public key")
)

// Sign 保留兼容旧接口：生成一对新密钥并返回原始字符串公钥和签名.
func Sign(msg string) (string, string) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		return "", ""
	}
	signature, err := SignBytes(privateKey, []byte(msg))
	if err != nil {
		return "", ""
	}
	return string(publicKey), string(signature)
}

// Verify 保留兼容旧接口：使用原始字节字符串验签.
func Verify(publicKey, msg, signature string) bool {
	return VerifyBytes(ed25519.PublicKey(publicKey), []byte(msg), []byte(signature))
}

// GenerateKeyPair 生成一对 Ed25519 密钥.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// GenerateKeyPEM 生成 PEM 编码的 Ed25519 密钥对.
func GenerateKeyPEM() ([]byte, []byte, error) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	privatePEM, err := MarshalPrivateKeyPEM(privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicPEM, err := MarshalPublicKeyPEM(publicKey)
	if err != nil {
		return nil, nil, err
	}
	return privatePEM, publicPEM, nil
}

// WriteKeyPair 生成并写入 PEM 编码的 Ed25519 密钥对.
func WriteKeyPair(privatePath, publicPath string) error {
	privatePEM, publicPEM, err := GenerateKeyPEM()
	if err != nil {
		return err
	}
	if err := writePEMFile(privatePath, privatePEM, 0o600); err != nil {
		return err
	}
	return writePEMFile(publicPath, publicPEM, 0o644)
}

// MarshalPrivateKeyPEM 将私钥编码为 PKCS#8 PEM.
func MarshalPrivateKeyPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// MarshalPublicKeyPEM 将公钥编码为 PKIX PEM.
func MarshalPublicKeyPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// ReadPrivateKey 从 PEM 文件读取 Ed25519 私钥.
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- this helper intentionally reads a caller-provided key path.
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	return ParsePrivateKeyPEM(data)
}

// ReadPublicKey 从 PEM 文件读取 Ed25519 公钥.
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- this helper intentionally reads a caller-provided key path.
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	return ParsePublicKeyPEM(data)
}

// ParsePrivateKeyPEM 从 PEM 内容中解析 Ed25519 私钥.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPrivateKey
	}
	switch block.Type {
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, ErrInvalidPrivateKey
		}
		return append(ed25519.PrivateKey(nil), block.Bytes...), nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	default:
		return nil, ErrInvalidPrivateKey
	}
}

// ParsePublicKeyPEM 从 PEM 内容中解析 Ed25519 公钥.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPublicKey
	}
	switch block.Type {
	case "ED25519 PUBLIC KEY":
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, ErrInvalidPublicKey
		}
		return append(ed25519.PublicKey(nil), block.Bytes...), nil
	case "PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, ErrInvalidPublicKey
		}
		return append(ed25519.PublicKey(nil), key...), nil
	default:
		return nil, ErrInvalidPublicKey
	}
}

// SignBytes 使用 Ed25519 私钥签名字节数据.
func SignBytes(privateKey ed25519.PrivateKey, msg []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	return ed25519.Sign(privateKey, msg), nil
}

// SignBase64 使用 Ed25519 私钥签名并返回 Base64.
func SignBase64(privateKey ed25519.PrivateKey, msg []byte) (string, error) {
	signature, err := SignBytes(privateKey, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyBytes 使用 Ed25519 公钥验证签名.
func VerifyBytes(publicKey ed25519.PublicKey, msg, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, msg, signature)
}

// VerifyBase64 使用 Ed25519 公钥验证 Base64 编码签名.
func VerifyBase64(publicKey ed25519.PublicKey, msg []byte, signature string) bool {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return VerifyBytes(publicKey, msg, raw)
}

// SignFile 使用 PEM 私钥文件签名.
func SignFile(msg []byte, privatePath string) ([]byte, error) {
	privateKey, err := ReadPrivateKey(privatePath)
	if err != nil {
		return nil, err
	}
	return SignBytes(privateKey, msg)
}

// SignFileBase64 使用 PEM 私钥文件签名并返回 Base64.
func SignFileBase64(msg []byte, privatePath string) (string, error) {
	privateKey, err := ReadPrivateKey(privatePath)
	if err != nil {
		return "", err
	}
	return SignBase64(privateKey, msg)
}

// VerifyFile 使用 PEM 公钥文件验证签名.
func VerifyFile(msg []byte, publicPath string, signature []byte) (bool, error) {
	publicKey, err := ReadPublicKey(publicPath)
	if err != nil {
		return false, err
	}
	return VerifyBytes(publicKey, msg, signature), nil
}

// VerifyFileBase64 使用 PEM 公钥文件验证 Base64 编码签名.
func VerifyFileBase64(msg []byte, publicPath, signature string) (bool, error) {
	publicKey, err := ReadPublicKey(publicPath)
	if err != nil {
		return false, err
	}
	return VerifyBase64(publicKey, msg, signature), nil
}

func writePEMFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}
