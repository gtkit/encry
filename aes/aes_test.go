package aes_test

import (
	"crypto/sha256"
	"encoding/base64"
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

func TestCBCDecryptRejectsInvalid(t *testing.T) {
	key := "IgkibX71IEf382PT"
	decryptor := aes.NewCBC(key)

	tests := []struct {
		name  string
		input string
	}{
		// 合法 Base64(URL)，但首字节非 cipherFormatVersion（旧格式/伪造数据）
		{"非版本前缀", base64.URLEncoding.EncodeToString([]byte("not-a-versioned-ciphertext-blob!"))},
		{"非法 Base64", "%%%not-base64%%%"},
		{"空串", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptor.Decrypt(tt.input)
			require.Error(t, err)
		})
	}
}

func BenchmarkCBCEncryptAndDecrypt(b *testing.B) {
	b.ReportAllocs()
	key := "IgkibX71IEf382PT"

	aesn := aes.NewCBC(key)
	for b.Loop() {
		encryptString, _ := aesn.Encrypt([]byte("123456"))
		_, _ = aesn.Decrypt(encryptString)
	}
}

func BenchmarkGCMEncryptAndDecrypt(b *testing.B) {
	b.ReportAllocs()
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	for b.Loop() {
		cipherText, _ := gcm.Encrypt([]byte("123456"))
		_, _ = gcm.Decrypt(cipherText)
	}
}

func TestSha256(t *testing.T) {
	key := "IgkibX71IEf382PT" //
	keyb := sha256.Sum256([]byte(key))
	t.Log("key:", key, " len:", len(key))
	t.Log("keyb:", string(keyb[:]), " len:", len(string(keyb[:])))
}
