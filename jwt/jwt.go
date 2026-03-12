package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// GenerateSecureKey 生成安全的密钥.
func GenerateSecureKey() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	sec := base64.URLEncoding.EncodeToString(key)
	log.Println("JwtHmac 生成的密钥:", sec) // Changed from log.Println("密钥:", sec)
	return nil
}

// GenerateEd25519Keys 生成新密钥对（首次部署时使用）.
func GenerateEd25519Keys(priPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// 保存私钥（PEM格式）
	priBlock := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: priv,
	}
	if err := os.WriteFile(priPath, pem.EncodeToMemory(priBlock), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// 保存公钥（PEM格式）
	pubBlock := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: pub,
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	log.Println("JwtEd25519 密钥已生成并保存到:", priPath, pubPath)
	return nil
}

func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
