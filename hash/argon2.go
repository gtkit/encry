package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordManager struct {
	saltLength int
	time       uint32
	memory     uint32
	threads    uint8
	keyLen     uint32
}

// Argon2HashPassword 生成密码哈希.
func Argon2HashPassword(password string) (string, error) {
	pm := &PasswordManager{
		saltLength: 16,
		time:       3,
		memory:     64 * 1024, // 64MB
		threads:    4,
		keyLen:     32,
	}

	// 生成随机盐
	salt := make([]byte, pm.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成盐失败: %v", err)
	}

	// 使用Argon2生成哈希
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		pm.time,
		pm.memory,
		pm.threads,
		pm.keyLen,
	)

	// 编码为Base64
	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	// 返回格式化的哈希字符串
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		pm.memory,
		pm.time,
		pm.threads,
		saltBase64,
		hashBase64), nil
}

// Argon2VerifyPassword 验证密码.
// password 明文密码
// hash 哈希字符串
func Argon2VerifyPassword(password, hash string) bool {
	// 解析哈希字符串
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}

	// 提取参数
	// var version int
	var memory uint32
	var time uint32
	var threads uint8

	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// 使用相同参数计算哈希
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		time,
		memory,
		threads,
		uint32(len(expectedHash)),
	)

	// 安全比较哈希值
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}

// GenerateRandomPassword 生成随机密码.
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

	password := make([]byte, length)
	for i := range password {
		randomByte := make([]byte, 1)
		if _, err := rand.Read(randomByte); err != nil {
			return "", err
		}

		password[i] = charset[randomByte[0]%byte(len(charset))]
	}

	return string(password), nil
}
