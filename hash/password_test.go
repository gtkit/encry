package hash

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRandomPassword(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantLen int
	}{
		{"普通长度", 16, 16},
		{"长密码", 128, 128},
		{"零长度", 0, 0},
		{"负长度", -5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := GenerateRandomPassword(tt.length)
			require.NoError(t, err)
			require.Len(t, pwd, tt.wantLen)

			for _, r := range pwd {
				require.True(t, strings.ContainsRune(passwordCharset, r),
					"字符 %q 不在字符集内", r)
			}
		})
	}
}

func TestGenerateRandomPasswordUniqueness(t *testing.T) {
	a, err := GenerateRandomPassword(32)
	require.NoError(t, err)
	b, err := GenerateRandomPassword(32)
	require.NoError(t, err)

	require.NotEqual(t, a, b)
}
