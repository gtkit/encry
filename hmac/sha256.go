package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// Sha256 计算HmacSha256.
// key 是加密所使用的key.
// data 是加密的内容.
func Sha256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)

	return mac.Sum(nil)
}

// Sha256ToHex 将加密后的二进制转16进制字符串.
func Sha256ToHex(key, data []byte) string {
	return hex.EncodeToString(Sha256(key, data))
}

// Sha256ToBase64 将加密后的二进制转Base64字符串.
func Sha256ToBase64(key, data []byte) string {
	return base64.URLEncoding.EncodeToString(Sha256(key, data))
}

// Sha256Verify 验证签名是否正确.
// key 是加密所使用的key.
// value 是加密的内容.
// sign 是加密后的字符串.
// 返回true表示验证成功，false表示验证失败.
func Sha256Verify(key, value, sign string) bool {
	expected := Sha256([]byte(key), []byte(value))
	for _, candidate := range signatureCandidates(sign) {
		if hmac.Equal(candidate, expected) {
			return true
		}
	}
	return false
}
