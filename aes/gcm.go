package aes

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

const gcmCipherFormatVersion byte = 1

var _ AES = (*GCM)(nil)

// GCM 提供 AES-GCM 加解密能力，默认使用随机 nonce 并将其前置到密文中.
type GCM struct {
	aesImpl
}

// NewGCM 创建一个新的 AES-GCM 实例.
func NewGCM(key string) *GCM {
	return &GCM{
		aesImpl: newAESImpl(key),
	}
}

// Encrypt 使用 AES-GCM 加密，不附带额外认证数据.
func (g *GCM) Encrypt(plainText []byte) (string, error) {
	return g.EncryptWithAAD(plainText, nil)
}

// Decrypt 使用 AES-GCM 解密，不附带额外认证数据.
func (g *GCM) Decrypt(cipherText string) (string, error) {
	plainText, err := g.DecryptWithAAD(cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

// EncryptWithAAD 使用 AES-GCM 加密，并绑定额外认证数据.
func (g *GCM) EncryptWithAAD(plainText, aad []byte) (string, error) {
	block, err := stdaes.NewCipher(g.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encrypted := make([]byte, 1+len(nonce))
	encrypted[0] = gcmCipherFormatVersion
	copy(encrypted[1:], nonce)
	encrypted = aead.Seal(encrypted, nonce, plainText, aad)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptWithAAD 使用 AES-GCM 解密，并校验额外认证数据.
func (g *GCM) DecryptWithAAD(cipherText string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	block, err := stdaes.NewCipher(g.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(raw) < 1+aead.NonceSize() || raw[0] != gcmCipherFormatVersion {
		return nil, errInvalidCiphertext
	}

	nonce := raw[1 : 1+aead.NonceSize()]
	cipherPayload := raw[1+aead.NonceSize():]
	return aead.Open(nil, nonce, cipherPayload, aad)
}
