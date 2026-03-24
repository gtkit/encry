package sha1_test

import (
	"os"
	"path/filepath"
	"testing"

	encrysha1 "github.com/gtkit/encry/sha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA1StringAndVerify(t *testing.T) {
	sum := encrysha1.String("hello")
	assert.Equal(t, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", sum)
	assert.True(t, encrysha1.VerifyString("hello", sum))
	assert.False(t, encrysha1.VerifyString("world", sum))
}

func TestSHA1File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sha1.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))

	sum, err := encrysha1.File(path)
	require.NoError(t, err)
	assert.Equal(t, encrysha1.String("hello"), sum)
}
