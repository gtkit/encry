// Package ecdh 提供椭圆曲线 Diffie-Hellman 密钥协商（基于 crypto/ecdh）。
//
// 双方各自生成密钥对、交换公钥，即可各自算出相同的共享密钥。默认使用 X25519。
//
// 注意：协商出的共享密钥不应直接用作对称加密密钥，应再经 hkdf 等 KDF 派生。
package ecdh

import (
	"crypto/ecdh"
	"crypto/rand"
)

// GenerateX25519 生成一对 X25519 密钥。
func GenerateX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// Generate 使用指定曲线生成密钥对（如 ecdh.P256()、ecdh.X25519()）。
func Generate(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

// SharedSecret 用本方私钥与对端公钥计算共享密钥。
func SharedSecret(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(peerPub)
}

// ParsePublicKey 用指定曲线从字节解析对端公钥。
func ParsePublicKey(curve ecdh.Curve, b []byte) (*ecdh.PublicKey, error) {
	return curve.NewPublicKey(b)
}

// ParsePrivateKey 用指定曲线从字节解析私钥。
func ParsePrivateKey(curve ecdh.Curve, b []byte) (*ecdh.PrivateKey, error) {
	return curve.NewPrivateKey(b)
}
