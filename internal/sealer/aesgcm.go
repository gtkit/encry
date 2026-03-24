package sealer

import (
	"fmt"
	"strings"

	encryaes "github.com/gtkit/encry/aes"
	"github.com/gtkit/encry/internal/keyring"
)

// AESGCMService 基于 kid 密钥环提供 AES-GCM 加解密.
type AESGCMService struct {
	ring *keyring.Ring[string]
}

// NewAESGCM 创建一个新的 AES-GCM 服务.
func NewAESGCM(ring *keyring.Ring[string]) *AESGCMService {
	return &AESGCMService{ring: ring}
}

// Encrypt 使用当前 active kid 对数据加密，并将 kid 前置到输出中.
func (s *AESGCMService) Encrypt(plainText, aad []byte) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	key, err := snapshot.Active()
	if err != nil {
		return "", err
	}

	gcm := encryaes.NewGCM(key)
	cipherText, err := gcm.EncryptWithAAD(plainText, aad)
	if err != nil {
		return "", err
	}
	return snapshot.ActiveKID + "." + cipherText, nil
}

// Decrypt 根据前置 kid 选择密钥并解密.
func (s *AESGCMService) Decrypt(token string, aad []byte) ([]byte, error) {
	kid, cipherText, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("invalid token format")
	}

	snapshot, err := s.ring.Current()
	if err != nil {
		return nil, err
	}
	key, ok := snapshot.Get(kid)
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}

	gcm := encryaes.NewGCM(key)
	return gcm.DecryptWithAAD(cipherText, aad)
}
