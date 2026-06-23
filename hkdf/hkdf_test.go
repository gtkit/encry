package hkdf_test

import (
	"fmt"
	"testing"

	"github.com/gtkit/encry/hkdf"
	"github.com/stretchr/testify/require"
)

func TestDeriveDeterministicAndLength(t *testing.T) {
	secret := []byte("shared-secret")
	salt := []byte("salt")

	tests := []struct {
		name   string
		keyLen int
	}{
		{"16字节", 16},
		{"32字节", 32},
		{"64字节", 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := hkdf.Derive(secret, salt, "ctx", tt.keyLen)
			require.NoError(t, err)
			require.Len(t, a, tt.keyLen)

			b, err := hkdf.Derive(secret, salt, "ctx", tt.keyLen)
			require.NoError(t, err)
			require.Equal(t, a, b) // 确定性
		})
	}
}

func TestDeriveDifferentInfo(t *testing.T) {
	secret := []byte("s")
	k1, err := hkdf.Derive(secret, nil, "info-a", 32)
	require.NoError(t, err)
	k2, err := hkdf.Derive(secret, nil, "info-b", 32)
	require.NoError(t, err)
	require.NotEqual(t, k1, k2)
}

func TestDeriveInvalidLength(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		_, err := hkdf.Derive([]byte("s"), nil, "i", n)
		require.ErrorIs(t, err, hkdf.ErrInvalidKeyLength)
		_, err = hkdf.DeriveSHA512([]byte("s"), nil, "i", n)
		require.ErrorIs(t, err, hkdf.ErrInvalidKeyLength)
	}
}

func TestDeriveSHA512(t *testing.T) {
	k, err := hkdf.DeriveSHA512([]byte("s"), []byte("salt"), "i", 48)
	require.NoError(t, err)
	require.Len(t, k, 48)
}

func ExampleDerive() {
	key, err := hkdf.Derive([]byte("shared-secret"), []byte("salt"), "app:v1", 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(key))
	// Output: 32
}
