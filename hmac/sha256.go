// @Author 2024/1/15 18:06:00
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// Sha256 计算HmacSha256
// key 是加密所使用的key
// data 是加密的内容
func Sha256(key string, data string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// Sha256ToHex 将加密后的二进制转16进制字符串
func Sha256ToHex(key string, data string) string {
	return hex.EncodeToString(Sha256(key, data))
}

// Sha256ToBase64 将加密后的二进制转Base64字符串
func Sha256ToBase64(key string, data string) string {
	return base64.URLEncoding.EncodeToString(Sha256(key, data))
}
