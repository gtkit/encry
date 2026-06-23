// Package hpke 提供混合公钥加密 HPKE（RFC9180，基于 go1.26 的 crypto/hpke）。
//
// 只持有接收方公钥即可加密；解密需对应私钥。相比"用 RSA 直接加密大数据"的反模式，
// HPKE 内部用 KEM 协商对称密钥再做 AEAD，没有明文长度限制、且更安全。
//
// 默认套件：DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305。
// info 是可选的上下文绑定（域分隔）：Seal 与 Open 必须使用相同的 info。
package hpke

import (
	"crypto/ecdh"
	stdhpke "crypto/hpke"
	"crypto/rand"
	"encoding/base64"
)

// GenerateKeyPair 生成一对 X25519 密钥用于 HPKE。
func GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// ParsePublicKey 从字节解析 X25519 公钥。
func ParsePublicKey(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

// Seal 用接收方公钥加密明文，返回 Base64（封装密钥 enc 与密文的拼接）。
func Seal(pub *ecdh.PublicKey, info, plainText []byte) (string, error) {
	pk, err := stdhpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return "", err
	}
	blob, err := stdhpke.Seal(pk, stdhpke.HKDFSHA256(), stdhpke.ChaCha20Poly1305(), info, plainText)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Open 用接收方私钥解密 Seal 产生的密文。info 必须与加密时一致。
func Open(priv *ecdh.PrivateKey, info []byte, cipherText string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	sk, err := stdhpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return stdhpke.Open(sk, stdhpke.HKDFSHA256(), stdhpke.ChaCha20Poly1305(), info, raw)
}
