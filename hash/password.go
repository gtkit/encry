package hash

import (
	"crypto/rand"
)

// passwordCharset 是随机密码使用的字符集.
const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

// GenerateRandomPassword 生成指定长度的随机密码.
// 使用拒绝采样保证字符在字符集上均匀分布，避免取模偏置.
// length <= 0 时返回空字符串与 nil 错误.
func GenerateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	n := len(passwordCharset)
	// 拒绝采样阈值：丢弃落在 [limit, 256) 的字节，使取模分布均匀.
	limit := 256 - (256 % n)

	password := make([]byte, 0, length)
	buf := make([]byte, length)
	for len(password) < length {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			password = append(password, passwordCharset[int(b)%n])
			if len(password) == length {
				break
			}
		}
	}

	return string(password), nil
}
