package hmac_test

import (
	"testing"

	encryhmac "github.com/gtkit/encry/hmac"
	"github.com/stretchr/testify/assert"
)

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
