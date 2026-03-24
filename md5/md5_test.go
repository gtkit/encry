package md5_test

import (
	"os"
	"path/filepath"
	"testing"

	encrymd5 "github.com/gtkit/encry/md5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMD5StringAndVerify(t *testing.T) {
	sum := encrymd5.String("hello")
	assert.Equal(t, "5d41402abc4b2a76b9719d911017c592", sum)
	assert.True(t, encrymd5.VerifyString("hello", sum))
	assert.False(t, encrymd5.VerifyString("world", sum))
}

func TestMD5File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "md5.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))

	sum, err := encrymd5.File(path)
	require.NoError(t, err)
	assert.Equal(t, encrymd5.String("hello"), sum)
}
