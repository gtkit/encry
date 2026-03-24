package aes_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/gtkit/encry/aes"
	"github.com/stretchr/testify/require"
)

func TestCBCEncrypt(t *testing.T) {
	key := "IgkibX71IEf382PT"
	plaintext := "123456"

	encryptor := aes.NewCBC(key)
	decryptor := aes.NewCBC(key)

	encryptString, err := encryptor.Encrypt([]byte(plaintext))
	require.NoError(t, err)

	decryptString, err := decryptor.Decrypt(encryptString)
	require.NoError(t, err)
	require.Equal(t, plaintext, decryptString)
}

func TestCFBEncrypt(t *testing.T) {
	key := "IgkibX71IEf382P3"
	plaintext := "123456"

	encryptor := aes.NewCFB(key)
	decryptor := aes.NewCFB(key)

	encryptString, err := encryptor.Encrypt([]byte(plaintext))
	require.NoError(t, err)

	decryptString, err := decryptor.Decrypt(encryptString)
	require.NoError(t, err)
	require.Equal(t, plaintext, decryptString)
}

func BenchmarkEncryptAndDecrypt(b *testing.B) {
	key := "IgkibX71IEf382PT"

	aesn := aes.NewCBC(key)
	for b.Loop() {
		encryptString, _ := aesn.Encrypt([]byte("123456"))
		_, _ = aesn.Decrypt(encryptString)
	}
}

func TestSha256(t *testing.T) {
	key := "IgkibX71IEf382PT" //
	keyb := sha256.Sum256([]byte(key))
	t.Log("key:", key, " len:", len(key))
	fmt.Println("keyb:", string(keyb[:]), " len:", len(string(keyb[:])))
}
