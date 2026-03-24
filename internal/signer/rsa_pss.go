package signer

import (
	"crypto"
	stdrsa "crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gtkit/encry/internal/keyring"
	encryrsa "github.com/gtkit/encry/rsa"
)

// RSAPSSService 基于 kid 密钥环提供 RSA-PSS 签名与验签.
type RSAPSSService struct {
	ring *keyring.Ring[keyring.RSAKeyPair]
	hash crypto.Hash
	opts *stdrsa.PSSOptions
}

// NewRSAPSS 创建一个新的 RSA-PSS 服务.
func NewRSAPSS(ring *keyring.Ring[keyring.RSAKeyPair], hash crypto.Hash, opts *stdrsa.PSSOptions) *RSAPSSService {
	return &RSAPSSService{
		ring: ring,
		hash: hash,
		opts: opts,
	}
}

// Sign 使用当前 active kid 对 payload 签名，并将 kid 前置到输出中.
func (s *RSAPSSService) Sign(payload []byte) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	keyPair, err := snapshot.Active()
	if err != nil {
		return "", err
	}

	signature, err := encryrsa.SignPSSWithPrivateKey(keyPair.Private, payload, s.hash, s.opts)
	if err != nil {
		return "", err
	}
	return snapshot.ActiveKID + "." + base64.StdEncoding.EncodeToString(signature), nil
}

// Verify 使用默认 hash 和 PSSOptions 验签.
func (s *RSAPSSService) Verify(payload []byte, signed string) (bool, error) {
	return s.VerifyWith(payload, signed, s.hash, s.opts)
}

// VerifyWith 使用指定 hash 和 PSSOptions 验签.
func (s *RSAPSSService) VerifyWith(payload []byte, signed string, hash crypto.Hash, opts *stdrsa.PSSOptions) (bool, error) {
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
	keyPair, ok := snapshot.Get(kid)
	if !ok {
		return false, fmt.Errorf("unknown kid %q", kid)
	}

	err = encryrsa.VerifyPSSWithPublicKey(keyPair.Public, payload, signature, hash, opts)
	return err == nil, nil
}
