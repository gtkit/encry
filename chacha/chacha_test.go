package chacha_test

import (
	"strings"
	"testing"

	"github.com/gtkit/encry/chacha"
	"github.com/stretchr/testify/require"
)

func key32() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestNewChaChaInvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"短", []byte("short")},
		{"空", nil},
		{"超长", make([]byte, 33)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := chacha.NewChaCha(tt.key)
			require.ErrorIs(t, err, chacha.ErrInvalidKeySize)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	c, err := chacha.NewChaCha(key32())
	require.NoError(t, err)

	tests := []struct {
		name      string
		plainText []byte
		aad       []byte
	}{
		{"简单", []byte("hello chacha"), nil},
		{"带aad", []byte("payload"), []byte("ctx")},
		{"空明文", []byte(""), []byte("aad")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := c.EncryptWithAAD(tt.plainText, tt.aad)
			require.NoError(t, err)

			got, err := c.DecryptWithAAD(enc, tt.aad)
			require.NoError(t, err)
			require.Equal(t, string(tt.plainText), string(got))
		})
	}
}

func TestEncryptRandomNonce(t *testing.T) {
	c, _ := chacha.NewChaCha(key32())
	a, err := c.Encrypt([]byte("same"))
	require.NoError(t, err)
	b, err := c.Encrypt([]byte("same"))
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestDecryptErrors(t *testing.T) {
	c, _ := chacha.NewChaCha(key32())
	valid, err := c.EncryptWithAAD([]byte("data"), []byte("aad"))
	require.NoError(t, err)

	t.Run("非法base64", func(t *testing.T) {
		_, err := c.Decrypt("!!!notb64!!!")
		require.Error(t, err)
	})
	t.Run("太短", func(t *testing.T) {
		_, err := c.Decrypt("AAAA")
		require.ErrorIs(t, err, chacha.ErrInvalidCiphertext)
	})
	t.Run("aad不匹配", func(t *testing.T) {
		_, err := c.DecryptWithAAD(valid, []byte("wrong"))
		require.Error(t, err)
	})
	t.Run("篡改密文", func(t *testing.T) {
		tampered := valid[:len(valid)-2] + strings.Repeat("A", 2)
		_, err := c.DecryptWithAAD(tampered, []byte("aad"))
		require.Error(t, err)
	})
}
