package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

var _ AES = (*cbc)(nil)

type cbc struct {
	key string // 秘钥：16, 24, 32字节长度的字符串，用于加密解密
	iv  []byte // 初始向量：一段固定长度的随机数，用于增强AES加密的强度。IV的长度通常为16字节（即128位），它必须与密钥一起使用
}

// New 创建一个新的Aes实例
func NewCBC(key string) AES {
	return &cbc{
		key: key,
		iv:  iv(),
	}
}

func (a *cbc) i() {}

// Encrypt 加密
// 加密模式: CBC
// 填充方式: PKCS5Padding
func (a *cbc) Encrypt(encryptBytes []byte) (string, error) {
	block, err := aes.NewCipher([]byte(a.key)) // NewCipher该函数限制了输入k的长度必须为16, 24或者32
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize() // 获取秘钥块的长度
	encryptBytes = pkcs5Padding(encryptBytes, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, []byte(a.iv)) // 加密模式,函数创建CBC加密器
	encrypted := make([]byte, len(encryptBytes))
	blockMode.CryptBlocks(encrypted, encryptBytes)
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// Decrypt 解密
// 加密模式: CBC
// 填充方式: PKCS5Padding
func (a *cbc) Decrypt(decryptStr string) (string, error) {
	decryptBytes, err := base64.URLEncoding.DecodeString(decryptStr)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(a.key)) // NewCipher该函数限制了输入k的长度必须为16, 24或者32,  分组秘钥
	if err != nil {
		return "", err
	}

	blockMode := cipher.NewCBCDecrypter(block, []byte(a.iv))

	decrypted := make([]byte, len(decryptBytes))

	blockMode.CryptBlocks(decrypted, decryptBytes)
	decrypted = pkcs5UnPadding(decrypted)
	return string(decrypted), nil
}

func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func pkcs5UnPadding(decrypted []byte) []byte {
	length := len(decrypted)
	unPadding := int(decrypted[length-1])
	return decrypted[:(length - unPadding)]
}
