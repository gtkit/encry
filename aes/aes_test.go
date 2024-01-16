package aes_test

import (
	"testing"

	"github.com/gtkit/encry/aes"
)

const (
	key = "IgkibX71IEf382PT"
	iv  = "IgkibX71IEf382PT"
)

func TestEncrypt(t *testing.T) {
	t.Log(aes.New(key, iv).Encrypt("123456"))
}

func TestDecrypt(t *testing.T) {
	t.Log(aes.New(key, iv).Decrypt("GO-ri84zevE-z1biJwfQPw=="))
}

func BenchmarkEncryptAndDecrypt(b *testing.B) {
	b.ResetTimer()
	aesn := aes.New(key, iv)
	for i := 0; i < b.N; i++ {
		encryptString, _ := aesn.Encrypt("123456")
		_, _ = aesn.Decrypt(encryptString)
	}
}
