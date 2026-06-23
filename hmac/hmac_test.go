package hmac_test

import (
	"encoding/base64"
	"testing"

	encryhmac "github.com/gtkit/encry/hmac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToBase64UsesStdEncoding(t *testing.T) {
	key := []byte("signing-key")
	data := []byte("payload")

	sha1B64 := encryhmac.Sha1ToBase64(string(key), string(data))
	sha256B64 := encryhmac.Sha256ToBase64(key, data)

	decoded1, err := base64.StdEncoding.DecodeString(sha1B64)
	require.NoError(t, err)
	assert.Len(t, decoded1, 20) // HMAC-SHA1

	decoded256, err := base64.StdEncoding.DecodeString(sha256B64)
	require.NoError(t, err)
	assert.Len(t, decoded256, 32) // HMAC-SHA256
}

func TestSha256VerifyAcceptsEncodedSignatures(t *testing.T) {
	key := []byte("signing-key")
	data := []byte("payload")

	assert.True(t, encryhmac.Sha256Verify(string(key), string(data), encryhmac.Sha256ToHex(key, data)))
	assert.True(t, encryhmac.Sha256Verify(string(key), string(data), encryhmac.Sha256ToBase64(key, data)))
}

func TestSha1VerifyAcceptsEncodedSignatures(t *testing.T) {
	key := "signing-key"
	data := "payload"

	assert.True(t, encryhmac.Sha1Verify(key, data, encryhmac.Sha1ToHex(key, data)))
	assert.True(t, encryhmac.Sha1Verify(key, data, encryhmac.Sha1ToBase64(key, data)))
}
