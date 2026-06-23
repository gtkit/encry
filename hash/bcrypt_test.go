package hash

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestEncryptAndVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		cost     []int
	}{
		{"default cost", "s3cr3t", nil},
		{"explicit low cost falls back to default", "pw", []int{4}},
		{"higher cost honored", "pw", []int{bcrypt.DefaultCost + 1}},
		{"empty password", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hashed, err := Encrypt(tt.password, tt.cost...)
			require.NoError(t, err)
			require.Len(t, hashed, Len)

			require.True(t, Verify(tt.password, hashed))
			require.False(t, Verify(tt.password+"x", hashed))

			require.NoError(t, Compare(tt.password, hashed))
			require.Error(t, Compare("wrong-"+tt.password, hashed))
		})
	}
}

func TestEncryptCostBoundaries(t *testing.T) {
	t.Parallel()

	// cost 大于默认值时按指定值生成，不需要刷新.
	hashed, err := Encrypt("pw", bcrypt.DefaultCost+2)
	require.NoError(t, err)
	require.False(t, HashNeedRefresh(hashed, bcrypt.DefaultCost+2))

	// 默认成本生成的哈希在要求更高成本时需要刷新.
	defHashed, err := Encrypt("pw")
	require.NoError(t, err)
	require.True(t, HashNeedRefresh(defHashed, bcrypt.DefaultCost+2))
	require.False(t, HashNeedRefresh(defHashed))
}

func TestEncryptTooLongPasswordReturnsError(t *testing.T) {
	t.Parallel()

	// bcrypt 限制明文不超过 72 字节，超过则返回错误.
	hashed, err := Encrypt(strings.Repeat("a", 100))
	require.Error(t, err)
	require.Empty(t, hashed)
}

func TestIsHashed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		str  string
		want bool
	}{
		{"too short", "short", false},
		{"empty", "", false},
		{"exactly 60 chars", strings.Repeat("x", Len), true},
		{"too long", strings.Repeat("x", Len+1), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, IsHashed(tt.str))
		})
	}

	// 真实哈希应被识别.
	hashed, err := Encrypt("pw")
	require.NoError(t, err)
	require.True(t, IsHashed(hashed))
}

func TestHashNeedRefreshInvalidHash(t *testing.T) {
	t.Parallel()

	// 非法哈希串无法解析成本，应判定为需要刷新.
	require.True(t, HashNeedRefresh("not-a-bcrypt-hash"))
}
