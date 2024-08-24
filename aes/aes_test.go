package aes_test

import (
	"testing"

	"github.com/gtkit/encry/aes"
)

func TestCBCEncrypt(t *testing.T) {

	var (
		key = "IgkibX71IEf382PT" //

	)
	cbc := aes.NewCBC(key)
	encryptString, err := cbc.Encrypt([]byte("123456"))
	if err != nil {
		t.Error("encrypt error", err)
	}
	t.Log(encryptString)

	decryptString, err := cbc.Decrypt(encryptString)
	if err != nil {
		t.Error("decrypt error", err)
	}
	t.Log(decryptString)

}

func TestCFBEncrypt(t *testing.T) {

	var (
		key = "IgkibX71IEf382P3" //

	)
	cbc := aes.NewCFB(key)
	encryptString, err := cbc.Encrypt([]byte("123456"))
	if err != nil {
		t.Error("encrypt error", err)
	}
	t.Log(encryptString)

	decryptString, err := cbc.Decrypt(encryptString)
	if err != nil {
		t.Error("decrypt error", err)
	}
	t.Log(decryptString)

}

func BenchmarkEncryptAndDecrypt(b *testing.B) {
	var (
		key = "IgkibX71IEf382PT" //
	)

	b.ResetTimer()
	aesn := aes.NewCBC(key)
	for i := 0; i < b.N; i++ {
		encryptString, _ := aesn.Encrypt([]byte("123456"))
		_, _ = aesn.Decrypt(encryptString)
	}
}
