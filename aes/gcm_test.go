package aes_test

import (
	"testing"

	"github.com/gtkit/encry/aes"
	"github.com/stretchr/testify/require"
)

func TestGCMEncryptDecrypt(t *testing.T) {
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.Encrypt([]byte("hello-gcm"))
	require.NoError(t, err)

	plainText, err := gcm.Decrypt(cipherText)
	require.NoError(t, err)
	require.Equal(t, "hello-gcm", plainText)
}

func TestGCMEncryptDecryptWithAAD(t *testing.T) {
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.EncryptWithAAD([]byte("hello-gcm"), []byte("aad"))
	require.NoError(t, err)

	plainText, err := gcm.DecryptWithAAD(cipherText, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("hello-gcm"), plainText)

	_, err = gcm.DecryptWithAAD(cipherText, []byte("wrong-aad"))
	require.Error(t, err)
}
