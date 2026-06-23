package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

// 默认 argon2id 参数，兼顾安全与性能（接近 OWASP 推荐）.
const (
	defaultSaltLength = 16
	defaultTime       = 3
	defaultMemory     = 64 * 1024 // 64MB
	defaultThreads    = 4
	defaultKeyLen     = 32
)

// Argon2 持有一组 argon2id 哈希参数，用于生成与校验密码哈希.
// 通过 NewArgon2 创建实例后字段只读，可被多个 goroutine 并发安全使用.
type Argon2 struct {
	saltLength int
	time       uint32
	memory     uint32
	threads    uint8
	keyLen     uint32
}

// PasswordManager 是 Argon2 的旧名.
//
// Deprecated: 请使用 Argon2 / NewArgon2.
type PasswordManager = Argon2

// Argon2Option 用于定制 Argon2 的参数（Functional Options）.
type Argon2Option func(*Argon2)

// WithTime 设置迭代次数（time cost）.
func WithTime(t uint32) Argon2Option {
	return func(a *Argon2) { a.time = t }
}

// WithMemory 设置内存用量，单位 KiB.
func WithMemory(kib uint32) Argon2Option {
	return func(a *Argon2) { a.memory = kib }
}

// WithThreads 设置并行度.
func WithThreads(p uint8) Argon2Option {
	return func(a *Argon2) { a.threads = p }
}

// WithSaltLen 设置随机盐的字节长度.
func WithSaltLen(n int) Argon2Option {
	return func(a *Argon2) { a.saltLength = n }
}

// WithKeyLen 设置派生哈希的字节长度.
func WithKeyLen(n uint32) Argon2Option {
	return func(a *Argon2) { a.keyLen = n }
}

// NewArgon2 使用默认参数创建实例，opts 可覆盖任意默认值.
func NewArgon2(opts ...Argon2Option) *Argon2 {
	a := &Argon2{
		saltLength: defaultSaltLength,
		time:       defaultTime,
		memory:     defaultMemory,
		threads:    defaultThreads,
		keyLen:     defaultKeyLen,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}
	// 防御性校验：非法（负/零）参数回退默认，避免 saltLength<=0 在 make 时 panic、
	// 或 keyLen/time/memory/threads 为 0 导致的弱参数/异常。
	if a.saltLength <= 0 {
		a.saltLength = defaultSaltLength
	}
	if a.time == 0 {
		a.time = defaultTime
	}
	if a.memory == 0 {
		a.memory = defaultMemory
	}
	if a.threads == 0 {
		a.threads = defaultThreads
	}
	if a.keyLen == 0 {
		a.keyLen = defaultKeyLen
	}
	return a
}

// Hash 用当前参数生成 argon2id 哈希，输出 PHC 标准串.
func (a *Argon2) Hash(password string) (string, error) {
	salt := make([]byte, a.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成盐失败: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		a.time,
		a.memory,
		a.threads,
		a.keyLen,
	)

	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.memory,
		a.time,
		a.threads,
		saltBase64,
		hashBase64), nil
}

// Verify 校验明文与 PHC 串是否匹配；参数从串中解析，与实例自身参数无关.
// 格式非法、版本不符或解码失败时返回 false（不 panic）.
func (a *Argon2) Verify(password, encoded string) bool {
	return Argon2VerifyPassword(password, encoded)
}

// Argon2HashPassword 用默认参数生成密码哈希.
func Argon2HashPassword(password string) (string, error) {
	return NewArgon2().Hash(password)
}

// Argon2VerifyPassword 验证密码.
// password 明文密码
// hash 哈希字符串.
func Argon2VerifyPassword(password, hash string) bool {
	// 解析哈希字符串
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}
	if parts[1] != "argon2id" {
		return false
	}

	// 提取参数
	var version int
	var memory uint32
	var time uint32
	var threads uint8

	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
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

	hashLen, ok := hashByteLen(int64(len(expectedHash)))
	if !ok {
		return false
	}

	// 使用相同参数计算哈希
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		time,
		memory,
		threads,
		hashLen,
	)

	// 安全比较哈希值
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}

func hashByteLen(n int64) (uint32, bool) {
	if n < 0 || n > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}
