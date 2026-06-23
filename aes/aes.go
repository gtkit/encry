package aes

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

// AES 是 CBC/CFB 共用的加解密接口（key 长度 16/24/32 对应 AES-128/192/256）。
//
// Deprecated: 该接口主要服务于未认证的 CBC/CFB（见 NewCBC/NewCFB）。推荐用 NewGCM
// （返回具体类型 *GCM）或 chacha/stream 包；v2 将收敛掉这个实现包内接口。
type AES interface {
	// Encrypt 加密
	Encrypt(encryptBytes []byte) (string, error)

	// Decrypt 解密
	Decrypt(decryptStr string) (string, error)
}

type aesImpl struct {
	key []byte // 秘钥：16, 24, 32字节长度的字符串，用于加密解密
}

const cipherFormatVersion byte = 1

var (
	errInvalidCiphertext = errors.New("invalid ciphertext")
	errInvalidPadding    = errors.New("invalid PKCS7 padding")
)

func newAESImpl(key string) aesImpl {
	return aesImpl{key: []byte(key)}
}

func newIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}
