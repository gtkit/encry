package sha1_test

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	encrysha1 "github.com/gtkit/encry/sha1"
	"github.com/stretchr/testify/require"
)

const helloHexSHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

func TestSHA1Forms(t *testing.T) {
	t.Parallel()

	data := []byte("hello")

	require.Equal(t, helloHexSHA1, encrysha1.String("hello"))
	require.Equal(t, helloHexSHA1, encrysha1.String("hello"))
	require.Equal(t, helloHexSHA1, encrysha1.Hex(data))

	wantBytes, err := hex.DecodeString(helloHexSHA1)
	require.NoError(t, err)

	sum := encrysha1.Sum(data)
	require.Equal(t, wantBytes, sum[:])
	require.Equal(t, wantBytes, encrysha1.Bytes(data))
}

func TestSHA1Reader(t *testing.T) {
	t.Parallel()

	got, err := encrysha1.Reader(strings.NewReader("hello"))
	require.NoError(t, err)
	require.Equal(t, helloHexSHA1, got)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

func TestSHA1ReaderError(t *testing.T) {
	t.Parallel()

	got, err := encrysha1.Reader(errReader{})
	require.Error(t, err)
	require.Empty(t, got)
}

func TestSHA1FileNotExist(t *testing.T) {
	t.Parallel()

	got, err := encrysha1.File(filepath.Join(t.TempDir(), "nope.txt"))
	require.Error(t, err)
	require.Empty(t, got)
}

func TestSHA1VerifyBytes(t *testing.T) {
	t.Parallel()

	data := []byte("hello")

	tests := []struct {
		name     string
		expected string
		want     bool
	}{
		{"match lowercase", helloHexSHA1, true},
		{"match uppercase", strings.ToUpper(helloHexSHA1), true},
		{"mismatch", hex.EncodeToString(make([]byte, 20)), false},
		{"invalid hex", "zzzz", false},
		{"wrong length", "abcd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, encrysha1.VerifyBytes(data, tt.expected))
			require.Equal(t, tt.want, encrysha1.VerifyString("hello", tt.expected))
		})
	}
}
