package md5

import (
	stdmd5 "crypto/md5" // #nosec G501 -- legacy compatibility package intentionally exposes MD5 helpers.
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// Sum 计算 MD5 摘要，兼容旧协议使用场景.
func Sum(data []byte) [stdmd5.Size]byte {
	return stdmd5.Sum(data) // #nosec G401 -- legacy compatibility package intentionally exposes MD5 helpers.
}

// Bytes 返回原始 MD5 摘要字节.
func Bytes(data []byte) []byte {
	sum := Sum(data)
	return append([]byte(nil), sum[:]...)
}

// Hex 返回十六进制编码的 MD5 摘要.
func Hex(data []byte) string {
	return hex.EncodeToString(Bytes(data))
}

// String 返回字符串的十六进制 MD5 摘要.
func String(text string) string {
	return Hex([]byte(text))
}

// Reader 计算 io.Reader 内容的十六进制 MD5 摘要.
func Reader(r io.Reader) (string, error) {
	h := stdmd5.New() // #nosec G401 -- legacy compatibility package intentionally exposes MD5 helpers.
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// File 计算文件内容的十六进制 MD5 摘要.
func File(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- this helper intentionally opens a caller-provided file path.
	if err != nil {
		return "", err
	}
	defer file.Close()
	return Reader(file)
}

// VerifyString 校验字符串的 MD5 十六进制摘要.
func VerifyString(text, expected string) bool {
	return verifyHexDigest([]byte(text), expected)
}

// VerifyBytes 校验字节数据的 MD5 十六进制摘要.
func VerifyBytes(data []byte, expected string) bool {
	return verifyHexDigest(data, expected)
}

func verifyHexDigest(data []byte, expected string) bool {
	decoded, err := hex.DecodeString(strings.ToLower(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(decoded, Bytes(data)) == 1
}
