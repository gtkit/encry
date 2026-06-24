package sqids_test

import (
	"strings"
	"testing"

	"github.com/gtkit/encry/sqids"
	"github.com/stretchr/testify/require"
)

func TestNewNilOptionNoPanic(t *testing.T) {
	// nil option 应被跳过而非 panic。
	h, err := sqids.New(nil)
	require.NoError(t, err)
	require.NotNil(t, h)

	encoded, err := h.Encode([]uint64{1})
	require.NoError(t, err)
	require.Equal(t, []uint64{1}, h.Decode(encoded))
}

func TestDefaultRoundTrip(t *testing.T) {
	h, err := sqids.New()
	require.NoError(t, err)

	nums := []uint64{1, 2, 3}
	encoded, err := h.Encode(nums)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	require.Equal(t, nums, h.Decode(encoded))
}

func TestWithMinLength(t *testing.T) {
	h, err := sqids.New(sqids.WithMinLength(10))
	require.NoError(t, err)

	encoded, err := h.Encode([]uint64{42})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(encoded), 10)
	require.Equal(t, []uint64{42}, h.Decode(encoded))
}

func TestWithAlphabet(t *testing.T) {
	const alphabet = "abcdefghijklmnop"
	h, err := sqids.New(sqids.WithAlphabet(alphabet))
	require.NoError(t, err)

	nums := []uint64{7, 8, 9}
	encoded, err := h.Encode(nums)
	require.NoError(t, err)
	for _, r := range encoded {
		require.True(t, strings.ContainsRune(alphabet, r), "字符 %q 不在字母表内", r)
	}
	require.Equal(t, nums, h.Decode(encoded))
}

func TestInvalidAlphabet(t *testing.T) {
	tests := []struct {
		name     string
		alphabet string
	}{
		{"过短", "ab"},
		{"重复字符", "aabbcc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sqids.New(sqids.WithAlphabet(tt.alphabet))
			require.Error(t, err)
		})
	}
}

func TestEncodeEmpty(t *testing.T) {
	h, err := sqids.New()
	require.NoError(t, err)

	encoded, err := h.Encode(nil)
	require.NoError(t, err)
	require.Empty(t, encoded)
}

func TestWithBlocklist(t *testing.T) {
	// 用空 blocklist 确保选项分支可用且不影响往返。
	h, err := sqids.New(sqids.WithBlocklist([]string{}))
	require.NoError(t, err)

	nums := []uint64{100, 200}
	encoded, err := h.Encode(nums)
	require.NoError(t, err)
	require.Equal(t, nums, h.Decode(encoded))
}
