package signer

import (
	"crypto"
	stdrsa "crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/gtkit/encry/internal/keyring"
	encryrsa "github.com/gtkit/encry/rsa"
)

// ManagedRSAPSSService 基于 metadata-aware kid 密钥环提供 RSA-PSS 签名与验签.
type ManagedRSAPSSService struct {
	ring *keyring.Ring[keyring.Record[keyring.RSAKeyPair]]
	hash crypto.Hash
	opts *stdrsa.PSSOptions
	now  func() time.Time
}

// NewManagedRSAPSS 创建一个 metadata-aware RSA-PSS 服务.
func NewManagedRSAPSS(ring *keyring.Ring[keyring.Record[keyring.RSAKeyPair]], hash crypto.Hash, opts *stdrsa.PSSOptions) *ManagedRSAPSSService {
	return &ManagedRSAPSSService{
		ring: ring,
		hash: hash,
		opts: opts,
		now:  time.Now,
	}
}

// Sign 使用 active kid 签名，并校验 metadata 生命周期.
func (s *ManagedRSAPSSService) Sign(payload []byte) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	record, err := keyring.ActiveRecord(snapshot, s.now())
	if err != nil {
		return "", err
	}

	signature, err := encryrsa.SignPSSWithPrivateKey(record.Key.Private, payload, s.hash, s.opts)
	if err != nil {
		return "", err
	}
	return record.Metadata.KID + "." + base64.StdEncoding.EncodeToString(signature), nil
}

// Verify 使用默认 hash 和 PSSOptions 验签.
func (s *ManagedRSAPSSService) Verify(payload []byte, signed string) (bool, error) {
	return s.VerifyWith(payload, signed, s.hash, s.opts)
}

// VerifyWith 使用指定 hash 和 PSSOptions 验签，并校验 metadata 生命周期.
func (s *ManagedRSAPSSService) VerifyWith(payload []byte, signed string, hash crypto.Hash, opts *stdrsa.PSSOptions) (bool, error) {
	kid, signatureB64, ok := strings.Cut(signed, ".")
	if !ok {
		return false, fmt.Errorf("invalid signature format")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, err
	}

	snapshot, err := s.ring.Current()
	if err != nil {
		return false, err
	}
	record, err := keyring.VerifyRecord(snapshot, kid, s.now())
	if err != nil {
		return false, err
	}

	return encryrsa.VerifyPSSWithPublicKey(record.Key.Public, payload, signature, hash, opts)
}
