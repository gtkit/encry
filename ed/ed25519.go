package ed

import (
	"crypto/ed25519"
	"crypto/rand"
)

// Sign ✅ 符合 Modern 原则的做法：
// 引入现代、高性能、难以误用的算法。
// Ed25519 生成密钥极快，且签名过程是确定性的，不需要随机数源。
func Sign(msg string) (string, string) {
	// 签名
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signature := ed25519.Sign(privateKey, []byte(msg))
	return string(publicKey), string(signature)
}

// Verify 验证签名.
func Verify(publicKey, msg, signature string) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(msg), []byte(signature))
}
