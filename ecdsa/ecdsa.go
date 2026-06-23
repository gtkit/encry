// Package ecdsa 提供 ECDSA 签名/验签与密钥 PEM 序列化（基于 crypto/ecdsa）。
//
// 默认曲线 P-256、摘要 SHA-256，签名为 ASN.1 DER 编码。风格对齐 ed / rsa 包。
package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

var (
	// ErrInvalidPrivateKey 表示 PEM 不是有效的 ECDSA 私钥。
	ErrInvalidPrivateKey = errors.New("ecdsa: invalid private key")
	// ErrInvalidPublicKey 表示 PEM 不是有效的 ECDSA 公钥。
	ErrInvalidPublicKey = errors.New("ecdsa: invalid public key")
)

// GenerateKey 使用默认曲线 P-256 生成密钥对。
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return GenerateKeyWithCurve(elliptic.P256())
}

// GenerateKeyWithCurve 使用指定曲线（如 elliptic.P384()）生成密钥对。
func GenerateKeyWithCurve(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// Sign 对消息做 SHA-256 摘要后用 ECDSA 签名，返回 ASN.1 DER 签名。
func Sign(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrInvalidPrivateKey
	}
	digest := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, priv, digest[:])
}

// SignBase64 签名并返回 Base64 字符串。
func SignBase64(priv *ecdsa.PrivateKey, msg []byte) (string, error) {
	sig, err := Sign(priv, msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify 校验签名是否匹配消息（对消息做 SHA-256 摘要），返回 (是否有效, 操作性错误)。
// 公钥为 nil 时返回 (false, ErrInvalidPublicKey)。
func Verify(pub *ecdsa.PublicKey, msg, sig []byte) (bool, error) {
	if pub == nil {
		return false, ErrInvalidPublicKey
	}
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, digest[:], sig), nil
}

// VerifyBase64 校验 Base64 编码的签名；Base64 非法时返回错误。
func VerifyBase64(pub *ecdsa.PublicKey, msg []byte, sigB64 string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, err
	}
	return Verify(pub, msg, sig)
}

// MarshalPrivateKeyPEM 将私钥编码为 PKCS#8 PEM。
func MarshalPrivateKeyPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKeyPEM 将公钥编码为 PKIX PEM。
func MarshalPublicKeyPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM 从 PKCS#8 PEM 解析 ECDSA 私钥。
func ParsePrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPrivateKey
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}
	return priv, nil
}

// ParsePublicKeyPEM 从 PKIX PEM 解析 ECDSA 公钥。
func ParsePublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPublicKey
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrInvalidPublicKey
	}
	return pub, nil
}
