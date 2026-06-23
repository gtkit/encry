// Package chacha 提供 XChaCha20-Poly1305 认证加密（AEAD）。
//
// 相比 AES-GCM，XChaCha20-Poly1305 不依赖 AES-NI 硬件加速，在移动端和无 AES-NI
// 的环境上更快；其 24 字节随机 nonce 在大量消息下的碰撞概率远低于 GCM 的 12 字节，
// 适合用随机 nonce 的场景。
//
// 密文格式：版本号(1字节) || 随机 nonce(24字节) || AEAD 密文，整体 Base64(Std) 编码。
package chacha

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const cipherFormatVersion byte = 1

var (
	// ErrInvalidKeySize 表示 key 长度不等于 32 字节。
	ErrInvalidKeySize = errors.New("chacha: key must be 32 bytes")
	// ErrInvalidCiphertext 表示密文格式非法或长度不足。
	ErrInvalidCiphertext = errors.New("chacha: invalid ciphertext")
)

// ChaCha 持有一个 XChaCha20-Poly1305 密钥，创建后只读，可被多个 goroutine 并发使用。
type ChaCha struct {
	key []byte
}

// NewChaCha 创建实例，key 必须为 32 字节（chacha20poly1305.KeySize）。
func NewChaCha(key []byte) (*ChaCha, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &ChaCha{key: dup}, nil
}

// Encrypt 加密明文，不附带额外认证数据。
func (c *ChaCha) Encrypt(plainText []byte) (string, error) {
	return c.EncryptWithAAD(plainText, nil)
}

// Decrypt 解密，不附带额外认证数据。
func (c *ChaCha) Decrypt(cipherText string) ([]byte, error) {
	return c.DecryptWithAAD(cipherText, nil)
}

// EncryptWithAAD 加密并绑定额外认证数据 aad。
func (c *ChaCha) EncryptWithAAD(plainText, aad []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encrypted := make([]byte, 1+len(nonce))
	encrypted[0] = cipherFormatVersion
	copy(encrypted[1:], nonce)
	encrypted = aead.Seal(encrypted, nonce, plainText, aad)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptWithAAD 解密并校验额外认证数据 aad。
func (c *ChaCha) DecryptWithAAD(cipherText string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, err
	}

	if len(raw) < 1+aead.NonceSize() || raw[0] != cipherFormatVersion {
		return nil, ErrInvalidCiphertext
	}

	nonce := raw[1 : 1+aead.NonceSize()]
	payload := raw[1+aead.NonceSize():]
	return aead.Open(nil, nonce, payload, aad)
}
