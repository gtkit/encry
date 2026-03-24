package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"crypto/x509"
)

// GenerateSecureKey 生成安全的密钥.
func GenerateSecureKey() error {
	sec, err := GenerateSecureKeyString()
	if err != nil {
		return err
	}
	log.Println("JwtHmac 生成的密钥:", sec)
	return nil
}

// GenerateSecureKeyString 生成安全的 JWT HMAC 密钥字符串.
func GenerateSecureKeyString() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// GenerateEd25519Keys 生成新密钥对（首次部署时使用）.
func GenerateEd25519Keys(priPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(priPath), 0o700); err != nil {
		return fmt.Errorf("create private key dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		return fmt.Errorf("create public key dir: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	priBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateDER,
	}
	if err := os.WriteFile(priPath, pem.EncodeToMemory(priBlock), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
