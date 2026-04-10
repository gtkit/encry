package keyring

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWKSetJSON(t *testing.T) {
	now := time.Unix(1_710_000_000, 0).UTC()
	set := JWKSet{
		Keys: []JWK{{
			KID:       "2026-04",
			KTY:       "OKP",
			Use:       "sig",
			Alg:       "EdDSA",
			Status:    StatusActive,
			CreatedAt: now,
			Crv:       "Ed25519",
			X:         "abc123",
		}},
	}

	raw, err := set.JSON()
	require.NoError(t, err)
	require.Contains(t, string(raw), "\"kid\": \"2026-04\"")
	require.Contains(t, string(raw), "\"alg\": \"EdDSA\"")
}

func TestLoadMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "2026-04.json")
	content := []byte(`{"status":"retiring","created_at":"2026-04-01T00:00:00Z"}`)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	metadata, err := loadMetadata(path, "2026-04", "EdDSA", "sig")
	require.NoError(t, err)
	require.Equal(t, "2026-04", metadata.KID)
	require.Equal(t, "EdDSA", metadata.Algorithm)
	require.Equal(t, "sig", metadata.Use)
	require.Equal(t, StatusRetiring, metadata.Status)
	require.Equal(t, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), metadata.CreatedAt)
}
