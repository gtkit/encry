package signer

import (
	"fmt"
	"strings"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/keyring"
)

// Ed25519Service 基于 kid 密钥环提供签名与验签.
type Ed25519Service struct {
	ring *keyring.Ring[keyring.Ed25519KeyPair]
}

// NewEd25519 创建一个新的 Ed25519 服务.
func NewEd25519(ring *keyring.Ring[keyring.Ed25519KeyPair]) *Ed25519Service {
	return &Ed25519Service{ring: ring}
}

// Sign 使用当前 active kid 对 payload 签名，并将 kid 前置到输出中.
func (s *Ed25519Service) Sign(payload []byte) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	keyPair, err := snapshot.Active()
	if err != nil {
		return "", err
	}

	signature, err := ed.SignBase64(keyPair.Private, payload)
	if err != nil {
		return "", err
	}
	return snapshot.ActiveKID + "." + signature, nil
}

// Verify 根据前置 kid 选择公钥并验证签名.
func (s *Ed25519Service) Verify(payload []byte, signed string) (bool, error) {
	kid, signature, ok := strings.Cut(signed, ".")
	if !ok {
		return false, fmt.Errorf("invalid signature format")
	}

	snapshot, err := s.ring.Current()
	if err != nil {
		return false, err
	}
	keyPair, ok := snapshot.Get(kid)
	if !ok {
		return false, fmt.Errorf("unknown kid %q", kid)
	}
	return ed.VerifyBase64(keyPair.Public, payload, signature)
}
