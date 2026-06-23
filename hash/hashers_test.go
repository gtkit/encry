package hash

import (
	"hash/fnv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFNVHashers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"ascii", "hello"},
		{"unicode", "世界"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := []byte(tt.input)

			// 与标准库 fnv 结果一致.
			h32 := fnv.New32a()
			_, _ = h32.Write(b)
			require.Equal(t, h32.Sum32(), StringFNV32a(tt.input))
			require.Equal(t, h32.Sum32(), BytesFNV32a(b))

			h64 := fnv.New64a()
			_, _ = h64.Write(b)
			require.Equal(t, h64.Sum64(), StringFNV64a(tt.input))
			require.Equal(t, h64.Sum64(), BytesFNV64a(b))
		})
	}
}

func TestDuplicateTrackerReset(t *testing.T) {
	t.Parallel()

	tracker := NewDuplicateTracker(DuplicateTrackerOptions{})

	require.False(t, tracker.IsDuplicate("a"))
	require.True(t, tracker.IsDuplicate("a"))

	tracker.Reset()

	// 重置后再次出现应视为首次.
	require.False(t, tracker.IsDuplicate("a"))
}

func TestDuplicateTrackerDefaultsApplied(t *testing.T) {
	t.Parallel()

	// 全零选项触发默认 TTL / MaxEntries / Now 分支.
	tracker := NewDuplicateTracker(DuplicateTrackerOptions{})
	require.False(t, tracker.IsDuplicate("x"))
	require.True(t, tracker.IsDuplicate("x"))
}

func TestPackageLevelDuplicateHelpers(t *testing.T) {
	// 不并行：操作进程级共享状态.
	CleanMap()

	require.False(t, IsDuplicate("dup-key"))
	require.True(t, IsDuplicate("dup-key"))

	CleanMap()
	require.False(t, IsDuplicate("dup-key"))
}
