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
