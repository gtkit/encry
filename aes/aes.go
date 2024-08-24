package aes

import (
	"crypto/aes"
	"crypto/rand"
)

type AES interface {
	i()
	// Encrypt 加密
	Encrypt(encryptBytes []byte) (string, error)

	// Decrypt 解密
	Decrypt(decryptStr string) (string, error)
}

func iv() []byte {
	ivdata := make([]byte, aes.BlockSize*2+16)
	if _, err := rand.Read(ivdata[:aes.BlockSize]); err != nil {
		return nil
	}
	return ivdata[:aes.BlockSize]
}
