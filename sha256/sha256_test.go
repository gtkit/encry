package sha256_test

import (
	"os"
	"path/filepath"
	"testing"

	encrysha256 "github.com/gtkit/encry/sha256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA256StringAndVerify(t *testing.T) {
	sum := encrysha256.String("hello")
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", sum)
	assert.True(t, encrysha256.VerifyString("hello", sum))
	assert.False(t, encrysha256.VerifyString("world", sum))
}

func TestSHA256Family(t *testing.T) {
	assert.Equal(t, "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193", encrysha256.String224("hello"))
	assert.NotEqual(t, encrysha256.String224("hello"), encrysha256.String224("world"))
	assert.Len(t, encrysha256.String384("hello"), 96)
	assert.Len(t, encrysha256.String512("hello"), 128)
}

func TestSHA256File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sha256.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))

	sum, err := encrysha256.File(path)
	require.NoError(t, err)
	assert.Equal(t, encrysha256.String("hello"), sum)
}
