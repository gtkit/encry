package aes

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

// AES-128:key长度16 字节
// AES-192:key长度24 字节
// AES-256:key长度32 字节
type AES interface {
	// Encrypt 加密
	Encrypt(encryptBytes []byte) (string, error)

	// Decrypt 解密
	Decrypt(decryptStr string) (string, error)
}

type aesImpl struct {
	key []byte // 秘钥：16, 24, 32字节长度的字符串，用于加密解密
	iv  []byte // 仅用于兼容旧版 CBC 密文解密，新版密文会自带随机 IV
}

const cipherFormatVersion byte = 1

var (
	errInvalidCiphertext = errors.New("invalid ciphertext")
	errInvalidPadding    = errors.New("invalid PKCS7 padding")
)

func newAESImpl(key string) aesImpl {
	legacyIV, _ := newIV()
	return aesImpl{
		key: []byte(key),
		iv:  legacyIV,
	}
}

func newIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}
