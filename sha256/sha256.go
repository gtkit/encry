package sha256

import (
	stdsha256 "crypto/sha256"
	stdsha512 "crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// New 返回一个 64 位 SHA256 十六进制字符串，保留兼容默认入口.
func New(text string) string {
	return String(text)
}

// Sum256 计算 SHA256 摘要.
func Sum256(data []byte) [stdsha256.Size]byte {
	return stdsha256.Sum256(data)
}

// Bytes 返回原始 SHA256 摘要字节.
func Bytes(data []byte) []byte {
	sum := Sum256(data)
	return append([]byte(nil), sum[:]...)
}

// Hex 返回 SHA256 十六进制摘要.
func Hex(data []byte) string {
	return hex.EncodeToString(Bytes(data))
}

// String 返回字符串的 SHA256 十六进制摘要.
func String(text string) string {
	return Hex([]byte(text))
}

// Reader 计算 io.Reader 内容的 SHA256 十六进制摘要.
func Reader(r io.Reader) (string, error) {
	h := stdsha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// File 计算文件内容的 SHA256 十六进制摘要.
func File(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- this helper intentionally opens a caller-provided file path.
	if err != nil {
		return "", err
	}
	defer file.Close()
	return Reader(file)
}

// VerifyString 校验字符串的 SHA256 十六进制摘要.
func VerifyString(text, expected string) bool {
	return verifyHexDigest([]byte(text), expected)
}

// VerifyBytes 校验字节数据的 SHA256 十六进制摘要.
func VerifyBytes(data []byte, expected string) bool {
	return verifyHexDigest(data, expected)
}

// Sum224 计算 SHA224 摘要.
func Sum224(data []byte) [stdsha256.Size224]byte {
	return stdsha256.Sum224(data)
}

// Hex224 返回 SHA224 十六进制摘要.
func Hex224(data []byte) string {
	sum := Sum224(data)
	return hex.EncodeToString(sum[:])
}

// String224 返回字符串的 SHA224 十六进制摘要.
func String224(text string) string {
	return Hex224([]byte(text))
}

// Sum384 计算 SHA384 摘要.
func Sum384(data []byte) [stdsha512.Size384]byte {
	return stdsha512.Sum384(data)
}

// Hex384 返回 SHA384 十六进制摘要.
func Hex384(data []byte) string {
	sum := Sum384(data)
	return hex.EncodeToString(sum[:])
}

// String384 返回字符串的 SHA384 十六进制摘要.
func String384(text string) string {
	return Hex384([]byte(text))
}

// Sum512 计算 SHA512 摘要.
func Sum512(data []byte) [stdsha512.Size]byte {
	return stdsha512.Sum512(data)
}

// Hex512 返回 SHA512 十六进制摘要.
func Hex512(data []byte) string {
	sum := Sum512(data)
	return hex.EncodeToString(sum[:])
}

// String512 返回字符串的 SHA512 十六进制摘要.
func String512(text string) string {
	return Hex512([]byte(text))
}

func verifyHexDigest(data []byte, expected string) bool {
	decoded, err := hex.DecodeString(strings.ToLower(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(decoded, Bytes(data)) == 1
}
