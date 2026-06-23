// Package hkdf 提供 RFC5869 的 HKDF（HMAC-based Extract-and-Expand）密钥派生。
//
// 用于把一段（可能不均匀的）密钥材料——例如 ECDH 协商出的共享密钥——扩展为
// 一个或多个强随机的对称密钥。默认使用 SHA-256。
package hkdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

// ErrInvalidKeyLength 表示请求的派生长度非法（<=0）。
var ErrInvalidKeyLength = errors.New("hkdf: key length must be positive")

// Derive 使用 HKDF-SHA256 从 secret 派生 keyLen 字节密钥。
// salt 可为 nil；info 用于域分隔，不同 info 派生出互不相关的密钥。
func Derive(secret, salt []byte, info string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, ErrInvalidKeyLength
	}
	return hkdf.Key(sha256.New, secret, salt, info, keyLen)
}

// DeriveSHA512 使用 HKDF-SHA512 派生，适合需要更长输出或更高安全裕度的场景。
func DeriveSHA512(secret, salt []byte, info string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, ErrInvalidKeyLength
	}
	return hkdf.Key(sha512.New, secret, salt, info, keyLen)
}
