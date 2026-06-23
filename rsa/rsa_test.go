package rsa_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/require"
)

func TestRSAEncryptionRoundTrip(t *testing.T) {
	dir := generateRSAKeys(t)
	pub := filepath.Join(dir, "public.pem")
	pri := filepath.Join(dir, "private.pem")

	tests := []struct {
		name  string
		plain []byte
		enc   func([]byte, string) (string, error)
		dec   func(string, string) ([]byte, error)
	}{
		{"oaep single", []byte("oaep-message"), rsa.EncryptOAEPBase64, rsa.DecryptOAEPBase64},
		{"oaep chunked large", []byte(strings.Repeat("oaep-block-", 80)), rsa.EncryptOAEPChunkedBase64, rsa.DecryptOAEPChunkedBase64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipherText, err := tt.enc(tt.plain, pub)
			require.NoError(t, err)

			decrypted, err := tt.dec(cipherText, pri)
			require.NoError(t, err)
			require.Equal(t, tt.plain, decrypted)
		})
	}
}

func TestRSAPSSSignVerify(t *testing.T) {
	dir := generateRSAKeys(t)
	pub := filepath.Join(dir, "public.pem")
	pri := filepath.Join(dir, "private.pem")

	const msg = "pss-message"
	signature, err := rsa.SignPSSBase64([]byte(msg), pri)
	require.NoError(t, err)

	tests := []struct {
		name    string
		message string
		wantOK  bool
	}{
		{"valid signature", msg, true},
		{"tampered message", "pss-tampered", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := rsa.VerifyPSSBase64([]byte(tt.message), pub, signature)
			require.NoError(t, err)
			require.Equal(t, tt.wantOK, ok)
		})
	}
}

func generateRSAKeys(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, rsa.GenerateRsaKey(2048, dir))
	return dir
}
