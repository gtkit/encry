package rc4

import (
	stdrc4 "crypto/rc4" // #nosec G503 -- legacy compatibility package intentionally exposes RC4 helpers.
	"encoding/base64"
)

// Apply 使用 RC4 对输入执行一次流变换，返回新的结果切片.
// RC4 是对称流密码，加密与解密是同一操作，统一用 Apply。
func Apply(key string, src []byte) ([]byte, error) {
	dst := append([]byte(nil), src...)
	if err := ApplyInPlace(key, dst); err != nil {
		return nil, err
	}
	return dst, nil
}

// ApplyInPlace 使用 RC4 对输入执行一次流变换，并原地写回结果.
func ApplyInPlace(key string, buf []byte) error {
	cipher, err := stdrc4.NewCipher([]byte(key)) // #nosec G405 -- legacy compatibility package intentionally exposes RC4 helpers.
	if err != nil {
		return err
	}
	cipher.XORKeyStream(buf, buf)
	return nil
}

// EncryptToBase64 使用 RC4 加密并编码为 Base64.
func EncryptToBase64(key string, plainText []byte) (string, error) {
	cipherText, err := Apply(key, plainText)
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
	return Apply(key, raw)
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
