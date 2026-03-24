package ed_test

import (
	"path/filepath"
	"testing"

	"github.com/gtkit/encry/ed"
	"github.com/stretchr/testify/require"
)

func TestEd25519PEMRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")

	require.NoError(t, ed.WriteKeyPair(privatePath, publicPath))

	signature, err := ed.SignFile([]byte("hello-ed25519"), privatePath)
	require.NoError(t, err)

	ok, err := ed.VerifyFile([]byte("hello-ed25519"), publicPath, signature)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestEd25519Base64Signature(t *testing.T) {
	publicKey, privateKey, err := ed.GenerateKeyPair()
	require.NoError(t, err)

	signature, err := ed.SignBase64(privateKey, []byte("hello-ed25519"))
	require.NoError(t, err)
	require.True(t, ed.VerifyBase64(publicKey, []byte("hello-ed25519"), signature))
	require.False(t, ed.VerifyBase64(publicKey, []byte("wrong"), signature))
}
