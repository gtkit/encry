package rc4

import (
	stdrc4 "crypto/rc4" //nolint:gosec //legacy compatibility
	"encoding/base64"
)

// New 保留兼容旧接口，返回一个新的加解密结果，不会原地修改传入切片.
func New(key string, str []byte) ([]byte, error) {
	return Apply(key, str)
}

// Apply 使用 RC4 对输入执行一次流变换，返回新的结果切片.
func Apply(key string, src []byte) ([]byte, error) {
	dst := append([]byte(nil), src...)
	if err := ApplyInPlace(key, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

// ApplyInPlace 使用 RC4 对输入执行一次流变换，并原地写回结果.
func ApplyInPlace(key string, buf []byte) error {
	cipher, err := stdrc4.NewCipher([]byte(key)) //nolint:gosec //legacy compatibility
	if err != nil {
		return err
	}
	cipher.XORKeyStream(buf, buf)
	return nil
}

// Encrypt 是 Apply 的语义化别名.
func Encrypt(key string, plainText []byte) ([]byte, error) {
	return Apply(key, plainText)
}

// Decrypt 是 Apply 的语义化别名.
func Decrypt(key string, cipherText []byte) ([]byte, error) {
	return Apply(key, cipherText)
}

// EncryptToBase64 使用 RC4 加密并编码为 Base64.
func EncryptToBase64(key string, plainText []byte) (string, error) {
	cipherText, err := Encrypt(key, plainText)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptFromBase64 解码 Base64 后执行 RC4 解密.
func DecryptFromBase64(key, cipherText string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	return Decrypt(key, raw)
}

// EncryptStringToBase64 使用 RC4 加密字符串并编码为 Base64.
func EncryptStringToBase64(key, plainText string) (string, error) {
	return EncryptToBase64(key, []byte(plainText))
}

// DecryptBase64ToString 解码 Base64 后执行 RC4 解密并返回字符串.
func DecryptBase64ToString(key, cipherText string) (string, error) {
	plainText, err := DecryptFromBase64(key, cipherText)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}
