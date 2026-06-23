package md5_test

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	encrymd5 "github.com/gtkit/encry/md5"
	"github.com/stretchr/testify/require"
)

const helloHexMD5 = "5d41402abc4b2a76b9719d911017c592"

func TestMD5Forms(t *testing.T) {
	t.Parallel()

	data := []byte("hello")

	require.Equal(t, helloHexMD5, encrymd5.New("hello"))
	require.Equal(t, helloHexMD5, encrymd5.String("hello"))
	require.Equal(t, helloHexMD5, encrymd5.Hex(data))

	wantBytes, err := hex.DecodeString(helloHexMD5)
	require.NoError(t, err)

	sum := encrymd5.Sum(data)
	require.Equal(t, wantBytes, sum[:])
	require.Equal(t, wantBytes, encrymd5.Bytes(data))
}

func TestMD5Reader(t *testing.T) {
	t.Parallel()

	got, err := encrymd5.Reader(strings.NewReader("hello"))
	require.NoError(t, err)
	require.Equal(t, helloHexMD5, got)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

func TestMD5ReaderError(t *testing.T) {
	t.Parallel()

	got, err := encrymd5.Reader(errReader{})
	require.Error(t, err)
	require.Empty(t, got)
}

func TestMD5FileNotExist(t *testing.T) {
	t.Parallel()

	got, err := encrymd5.File(filepath.Join(t.TempDir(), "nope.txt"))
	require.Error(t, err)
	require.Empty(t, got)
}

func TestMD5VerifyBytes(t *testing.T) {
	t.Parallel()

	data := []byte("hello")

	tests := []struct {
		name     string
		expected string
		want     bool
	}{
		{"match lowercase", helloHexMD5, true},
		{"match uppercase", strings.ToUpper(helloHexMD5), true},
		{"mismatch", hex.EncodeToString(make([]byte, 16)), false},
		{"invalid hex", "zzzz", false},
		{"wrong length", "abcd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, encrymd5.VerifyBytes(data, tt.expected))
			require.Equal(t, tt.want, encrymd5.VerifyString("hello", tt.expected))
		})
	}
}
