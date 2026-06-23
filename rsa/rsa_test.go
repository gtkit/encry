package rsa_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAEPEncryptDecrypt(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("oaep-message")

	cipherText, err := rsa.EncryptOAEPBase64(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.DecryptOAEPBase64(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestOAEPChunkedEncryptDecrypt(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte(strings.Repeat("oaep-block-", 80))

	cipherText, err := rsa.EncryptOAEPChunkedBase64(plainText, filepath.Join(dir, "public.pem"))
	require.NoError(t, err)

	decrypted, err := rsa.DecryptOAEPChunkedBase64(cipherText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestPSSSignVerify(t *testing.T) {
	dir := generateRSAKeys(t)
	plainText := []byte("pss-message")

	signature, err := rsa.SignPSSBase64(plainText, filepath.Join(dir, "private.pem"))
	require.NoError(t, err)

	ok, err := rsa.VerifyPSSBase64(plainText, filepath.Join(dir, "public.pem"), signature)
	require.NoError(t, err)
	require.True(t, ok)

	bad, err := rsa.VerifyPSSBase64([]byte("wrong"), filepath.Join(dir, "public.pem"), signature)
	require.NoError(t, err)
	require.False(t, bad)
}

func generateRSAKeys(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, rsa.GenerateRsaKey(2048, dir))
	return dir
}
