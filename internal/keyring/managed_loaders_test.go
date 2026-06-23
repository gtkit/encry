package keyring

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadStringKeyRecords(t *testing.T) {
	t.Parallel()

	t.Run("with sidecar metadata", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1.key"), []byte(" secret \n"), 0o600))
		meta := []byte(`{"status":"retiring","created_at":"2026-04-01T00:00:00Z"}`)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1.json"), meta, 0o600))

		records, err := LoadStringKeyRecords(dir, ".key", "HS256", "sig")
		require.NoError(t, err)
		require.Len(t, records, 1)

		rec := records["k1"]
		require.Equal(t, "secret", rec.Key)
		require.Equal(t, "k1", rec.Metadata.KID)
		require.Equal(t, "HS256", rec.Metadata.Algorithm)
		require.Equal(t, "sig", rec.Metadata.Use)
		require.Equal(t, StatusRetiring, rec.Metadata.Status)
		require.Equal(t, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), rec.Metadata.CreatedAt)
	})

	t.Run("without sidecar uses defaults", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1.key"), []byte("secret"), 0o600))

		records, err := LoadStringKeyRecords(dir, ".key", "HS256", "sig")
		require.NoError(t, err)
		rec := records["k1"]
		require.Equal(t, StatusActive, rec.Metadata.Status)
		require.Equal(t, "HS256", rec.Metadata.Algorithm)
	})

	t.Run("invalid metadata json errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1.key"), []byte("secret"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1.json"), []byte("{not json"), 0o600))

		_, err := LoadStringKeyRecords(dir, ".key", "HS256", "sig")
		require.Error(t, err)
	})

	t.Run("missing dir errors", func(t *testing.T) {
		t.Parallel()

		_, err := LoadStringKeyRecords(filepath.Join(t.TempDir(), "nope"), ".key", "HS256", "sig")
		require.Error(t, err)
	})
}

func TestLoadEd25519KeyPairRecords(t *testing.T) {
	t.Parallel()

	t.Run("with and without metadata", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeEd25519Pair(t, dir, "with-meta")
		writeEd25519Pair(t, dir, "no-meta")
		meta := []byte(`{"status":"retired"}`)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "with-meta", "metadata.json"), meta, 0o600))

		records, err := LoadEd25519KeyPairRecords(dir)
		require.NoError(t, err)
		require.Len(t, records, 2)

		require.Equal(t, StatusRetired, records["with-meta"].Metadata.Status)
		require.Equal(t, "EdDSA", records["with-meta"].Metadata.Algorithm)
		require.NotNil(t, records["with-meta"].Key.Private)

		// Default metadata when sidecar absent.
		require.Equal(t, StatusActive, records["no-meta"].Metadata.Status)
		require.Equal(t, "no-meta", records["no-meta"].Metadata.KID)
	})

	t.Run("missing private pem errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "bad"), 0o700))
		_, err := LoadEd25519KeyPairRecords(dir)
		require.Error(t, err)
	})

	t.Run("invalid metadata json errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeEd25519Pair(t, dir, "k1")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "k1", "metadata.json"), []byte("{bad"), 0o600))
		_, err := LoadEd25519KeyPairRecords(dir)
		require.Error(t, err)
	})

	t.Run("missing dir errors", func(t *testing.T) {
		t.Parallel()

		_, err := LoadEd25519KeyPairRecords(filepath.Join(t.TempDir(), "nope"))
		require.Error(t, err)
	})
}

func TestLoadRSAKeyPairRecords(t *testing.T) {
	t.Parallel()

	t.Run("default metadata", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeRSAPair(t, dir, "rsa-1")

		records, err := LoadRSAKeyPairRecords(dir)
		require.NoError(t, err)
		require.Len(t, records, 1)
		require.Equal(t, "PS512", records["rsa-1"].Metadata.Algorithm)
		require.Equal(t, StatusActive, records["rsa-1"].Metadata.Status)
		require.NotNil(t, records["rsa-1"].Key.Private)
	})

	t.Run("invalid public pem errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeRSAPair(t, dir, "rsa-1")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "rsa-1", "public.pem"), []byte("garbage"), 0o600))
		_, err := LoadRSAKeyPairRecords(dir)
		require.Error(t, err)
	})

	t.Run("missing dir errors", func(t *testing.T) {
		t.Parallel()

		_, err := LoadRSAKeyPairRecords(filepath.Join(t.TempDir(), "nope"))
		require.Error(t, err)
	})
}

func TestLoadMetadataReadError(t *testing.T) {
	t.Parallel()

	// A directory at the metadata path makes os.ReadFile fail with a
	// non-IsNotExist error, exercising the error branch of loadMetadata.
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "k1.json")
	require.NoError(t, os.Mkdir(metaPath, 0o700))

	_, err := loadMetadata(metaPath, "k1", "EdDSA", "sig")
	require.Error(t, err)
}
