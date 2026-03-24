package sealer

import (
	"fmt"
	"strings"
	"time"

	encryaes "github.com/gtkit/encry/aes"
	"github.com/gtkit/encry/internal/keyring"
)

// ManagedAESGCMService 基于 metadata-aware kid 密钥环提供 AES-GCM 服务.
type ManagedAESGCMService struct {
	ring *keyring.Ring[keyring.Record[string]]
	now  func() time.Time
}

// NewManagedAESGCM 创建一个 metadata-aware AES-GCM 服务.
func NewManagedAESGCM(ring *keyring.Ring[keyring.Record[string]]) *ManagedAESGCMService {
	return &ManagedAESGCMService{
		ring: ring,
		now:  time.Now,
	}
}

// Encrypt 使用 active kid 对数据加密，并校验 metadata 生命周期.
func (s *ManagedAESGCMService) Encrypt(plainText, aad []byte) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	record, err := keyring.ActiveRecord(snapshot, s.now())
	if err != nil {
		return "", err
	}

	gcm := encryaes.NewGCM(record.Key)
	cipherText, err := gcm.EncryptWithAAD(plainText, aad)
	if err != nil {
		return "", err
	}
	return record.Metadata.KID + "." + cipherText, nil
}

// Decrypt 根据 kid 选择密钥解密，并校验 metadata 生命周期.
func (s *ManagedAESGCMService) Decrypt(token string, aad []byte) ([]byte, error) {
	kid, cipherText, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("invalid token format")
	}

	snapshot, err := s.ring.Current()
	if err != nil {
		return nil, err
	}
	record, err := keyring.VerifyRecord(snapshot, kid, s.now())
	if err != nil {
		return nil, err
	}

	gcm := encryaes.NewGCM(record.Key)
	return gcm.DecryptWithAAD(cipherText, aad)
}
