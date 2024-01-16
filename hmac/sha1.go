package hmac

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec //used
	"encoding/hex"

	"github.com/gtkit/encry/base64"
)

// Sha1 计算HmacSha1.
// key 是加密所使用的key.
// data 是加密的内容.
func Sha1(key, value string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(value))
	return base64.Encode(mac.Sum(nil))
}

func sha1sum(key, value string) []byte {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// Sha1ToHex 将加密后的二进制转16进制字符串.
func Sha1ToHex(key string, data string) string {
	return hex.EncodeToString(sha1sum(key, data))
}

// Sha1ToBase64 将加密后的二进制转Base64字符串.
func Sha1ToBase64(key string, data string) string {
	return base64.Encode(sha1sum(key, data))
}
