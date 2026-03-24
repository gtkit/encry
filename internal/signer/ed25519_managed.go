package signer

import (
	"fmt"
	"strings"
	"time"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/keyring"
)

// ManagedEd25519Service 基于 metadata-aware kid 密钥环提供签名与验签.
type ManagedEd25519Service struct {
	ring *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]]
	now  func() time.Time
}

// NewManagedEd25519 创建一个 metadata-aware Ed25519 服务.
func NewManagedEd25519(ring *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]]) *ManagedEd25519Service {
	return &ManagedEd25519Service{
		ring: ring,
		now:  time.Now,
	}
}

// Sign 使用 active kid 签名，并校验 metadata 生命周期.
func (s *ManagedEd25519Service) Sign(payload []byte) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	record, err := keyring.ActiveRecord(snapshot, s.now())
	if err != nil {
		return "", err
	}

	signature, err := ed.SignBase64(record.Key.Private, payload)
	if err != nil {
		return "", err
	}
	return record.Metadata.KID + "." + signature, nil
}

// Verify 根据 kid 选择公钥验签，并校验 metadata 生命周期.
func (s *ManagedEd25519Service) Verify(payload []byte, signed string) (bool, error) {
	kid, signature, ok := strings.Cut(signed, ".")
	if !ok {
		return false, fmt.Errorf("invalid signature format")
	}

	snapshot, err := s.ring.Current()
	if err != nil {
		return false, err
	}
	record, err := keyring.VerifyRecord(snapshot, kid, s.now())
	if err != nil {
		return false, err
	}
	return ed.VerifyBase64(record.Key.Public, payload, signature), nil
}
