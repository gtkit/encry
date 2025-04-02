package aes

import (
	"crypto/aes"
	"crypto/rand"
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
	key string // 秘钥：16, 24, 32字节长度的字符串，用于加密解密
	iv  []byte // 初始向量：一段固定长度的随机数，用于增强AES加密的强度。IV的长度通常为16字节（即128位），它必须与密钥一起使用
}

func iv() []byte {
	ivdata := make([]byte, aes.BlockSize*2+16)
	if _, err := rand.Read(ivdata[:aes.BlockSize]); err != nil {
		return nil
	}
	return ivdata[:aes.BlockSize]
}
