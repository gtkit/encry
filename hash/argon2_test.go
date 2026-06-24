package hash

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashByteLenRejectsOverflow(t *testing.T) {
	length, ok := hashByteLen(int64(math.MaxUint32) + 1)

	require.False(t, ok)
	require.Zero(t, length)
}

func TestArgon2VerifyPasswordRoundTrip(t *testing.T) {
	password := "correct horse battery staple"

	encoded, err := Argon2HashPassword(password)
	require.NoError(t, err)

	require.True(t, Argon2VerifyPassword(password, encoded))
	require.False(t, Argon2VerifyPassword("wrong-password", encoded))
}

func TestArgon2HashPasswordRandomSalt(t *testing.T) {
	a, err := Argon2HashPassword("same-password")
	require.NoError(t, err)
	b, err := Argon2HashPassword("same-password")
	require.NoError(t, err)

	require.NotEqual(t, a, b, "随机盐应使两次输出不同")
}

func TestNewArgon2CustomParams(t *testing.T) {
	tests := []struct {
		name string
		opts []Argon2Option
		want string // PHC 串应包含的参数片段
	}{
		{
			name: "默认参数",
			opts: nil,
			want: "$m=65536,t=3,p=4$",
		},
		{
			name: "自定义内存与迭代",
			opts: []Argon2Option{WithMemory(32 * 1024), WithTime(2)},
			want: "$m=32768,t=2,p=4$",
		},
		{
			name: "自定义并行度",
			opts: []Argon2Option{WithThreads(2)},
			want: "$m=65536,t=3,p=2$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewArgon2(tt.opts...)
			encoded, err := a.Hash("hunter2")
			require.NoError(t, err)
			require.Contains(t, encoded, tt.want)

			// 自身校验
			require.True(t, a.Verify("hunter2", encoded))
			require.False(t, a.Verify("nope", encoded))

			// 跨实例校验：参数从串中解析，默认实例也能验证
			require.True(t, Argon2VerifyPassword("hunter2", encoded))
		})
	}
}

func TestNewArgon2SaltAndKeyLen(t *testing.T) {
	a := NewArgon2(WithSaltLen(8), WithKeyLen(16))

	encoded, err := a.Hash("hunter2")
	require.NoError(t, err)

	require.True(t, a.Verify("hunter2", encoded))
	require.False(t, a.Verify("nope", encoded))

	// 默认实例解析串内参数也能校验，盐/keyLen 从串中还原.
	require.True(t, Argon2VerifyPassword("hunter2", encoded))
}

func TestNewArgon2RejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []Argon2Option
	}{
		{"负 saltLen", []Argon2Option{WithSaltLen(-1)}},
		{"零 saltLen", []Argon2Option{WithSaltLen(0)}},
		{"零 keyLen", []Argon2Option{WithKeyLen(0)}},
		{"零 time/memory/threads", []Argon2Option{WithTime(0), WithMemory(0), WithThreads(0)}},
		{"nil option", []Argon2Option{nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewArgon2(tt.opts...)
			// 非法值已回退默认：不 panic，且能正常往返。
			encoded, err := a.Hash("pw")
			require.NoError(t, err)
			require.True(t, a.Verify("pw", encoded))
		})
	}
}

func TestArgon2VerifyPasswordVersionMismatch(t *testing.T) {
	// 版本号不等于 argon2.Version 时返回 false.
	require.False(t, Argon2VerifyPassword("pw",
		"$argon2id$v=1$m=65536,t=3,p=4$YWJj$YWJj"))
}

func TestArgon2VerifyPasswordRejectsDoSParams(t *testing.T) {
	// 构造格式合法但参数超大的 PHC 串：应被防 DoS 上限拦截，快速返回 false（不跑 argon2）。
	tests := []struct {
		name    string
		encoded string
	}{
		{"超大 memory", "$argon2id$v=19$m=2000000,t=3,p=4$YWJjYWJjYWJjYWJj$YWJjYWJjYWJjYWJj"},
		{"超大 time", "$argon2id$v=19$m=65536,t=99,p=4$YWJjYWJjYWJjYWJj$YWJjYWJjYWJjYWJj"},
		{"超大 threads", "$argon2id$v=19$m=65536,t=3,p=99$YWJjYWJjYWJjYWJj$YWJjYWJjYWJjYWJj"},
		{"零 memory", "$argon2id$v=19$m=0,t=3,p=4$YWJjYWJjYWJjYWJj$YWJjYWJjYWJjYWJj"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.False(t, Argon2VerifyPassword("pw", tt.encoded))
		})
	}
}

func TestArgon2VerifyPasswordInvalid(t *testing.T) {
	valid, err := Argon2HashPassword("pw")
	require.NoError(t, err)

	tests := []struct {
		name    string
		encoded string
	}{
		{"空串", ""},
		{"段数不足", "$argon2id$v=19$m=65536,t=3,p=4$abc"},
		{"算法不符", "$bcrypt$v=19$m=65536,t=3,p=4$YWJj$YWJj"},
		{"盐非法base64", "$argon2id$v=19$m=65536,t=3,p=4$!!!$YWJj"},
		{"哈希非法base64", "$argon2id$v=19$m=65536,t=3,p=4$YWJj$!!!"},
		{"参数段非法", "$argon2id$v=19$m=x,t=y,p=z$YWJj$YWJj"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.False(t, Argon2VerifyPassword("pw", tt.encoded))
		})
	}

	// 合法串确保上面用例不是因为别的原因失败
	require.True(t, Argon2VerifyPassword("pw", valid))
}
