package keyring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtkit/encry/ed"
	encryrsa "github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/require"
)

// writeEd25519Pair writes a freshly generated Ed25519 key pair under
// <dir>/<kid>/{private,public}.pem and returns the generated public key bytes.
func writeEd25519Pair(t *testing.T, dir, kid string) {
	t.Helper()

	pub, priv, err := ed.GenerateKeyPair()
	require.NoError(t, err)
	privPEM, err := ed.MarshalPrivateKeyPEM(priv)
	require.NoError(t, err)
	pubPEM, err := ed.MarshalPublicKeyPEM(pub)
	require.NoError(t, err)

	keyDir := filepath.Join(dir, kid)
	require.NoError(t, os.MkdirAll(keyDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(keyDir, "private.pem"), privPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(keyDir, "public.pem"), pubPEM, 0o600))
}

// writeRSAPair writes a freshly generated RSA key pair under
// <dir>/<kid>/{private,public}.pem.
func writeRSAPair(t *testing.T, dir, kid string) {
	t.Helper()

	priv, pub, err := encryrsa.GenerateKeyPair(2048)
	require.NoError(t, err)
	privPEM := encryrsa.MarshalPKCS1PrivateKeyPEM(priv)
	pubPEM := encryrsa.MarshalPKCS1PublicKeyPEM(pub)

	keyDir := filepath.Join(dir, kid)
	require.NoError(t, os.MkdirAll(keyDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(keyDir, "private.pem"), privPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(keyDir, "public.pem"), pubPEM, 0o600))
}

func TestLoadStringKeys(t *testing.T) {
	t.Parallel()

	t.Run("loads matching suffix and trims", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1.key"), []byte("  secret1\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k2.key"), []byte("secret2"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("nope"), 0o600))
		require.NoError(t, os.Mkdir(filepath.Join(dir, "sub.key"), 0o700))

		keys, err := LoadStringKeys(dir, ".key")
		require.NoError(t, err)
		require.Equal(t, map[string]string{"k1": "secret1", "k2": "secret2"}, keys)
	})

	t.Run("empty dir returns empty map", func(t *testing.T) {
		t.Parallel()

		keys, err := LoadStringKeys(t.TempDir(), ".key")
		require.NoError(t, err)
		require.Empty(t, keys)
	})

	t.Run("missing dir errors", func(t *testing.T) {
		t.Parallel()

		_, err := LoadStringKeys(filepath.Join(t.TempDir(), "nope"), ".key")
		require.Error(t, err)
	})
}

func TestLoadEd25519KeyPairs(t *testing.T) {
	t.Parallel()

	t.Run("loads pairs and skips files", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeEd25519Pair(t, dir, "2026-04")
		writeEd25519Pair(t, dir, "2026-05")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "stray.pem"), []byte("x"), 0o600))

		keys, err := LoadEd25519KeyPairs(dir)
		require.NoError(t, err)
		require.Len(t, keys, 2)
		require.NotNil(t, keys["2026-04"].Private)
		require.NotNil(t, keys["2026-04"].Public)
	})

	t.Run("missing dir errors", func(t *testing.T) {
		t.Parallel()

		_, err := LoadEd25519KeyPairs(filepath.Join(t.TempDir(), "nope"))
		require.Error(t, err)
	})

	t.Run("missing private pem errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "bad"), 0o700))
		_, err := LoadEd25519KeyPairs(dir)
		require.Error(t, err)
	})

	t.Run("invalid public pem errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeEd25519Pair(t, dir, "k1")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1", "public.pem"), []byte("garbage"), 0o600))
		_, err := LoadEd25519KeyPairs(dir)
		require.Error(t, err)
	})
}

func TestLoadRSAKeyPairs(t *testing.T) {
	t.Parallel()

	t.Run("loads pairs", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeRSAPair(t, dir, "rsa-1")

		keys, err := LoadRSAKeyPairs(dir)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.NotNil(t, keys["rsa-1"].Private)
		require.NotNil(t, keys["rsa-1"].Public)
	})

	t.Run("missing dir errors", func(t *testing.T) {
		t.Parallel()

		_, err := LoadRSAKeyPairs(filepath.Join(t.TempDir(), "nope"))
		require.Error(t, err)
	})

	t.Run("invalid private pem errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "bad"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bad", "private.pem"), []byte("garbage"), 0o600))
		_, err := LoadRSAKeyPairs(dir)
		require.Error(t, err)
	})
}
