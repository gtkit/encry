package aes_test

import (
	"crypto/sha256"
	"fmt"
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
	cfb := aes.NewCFB(key)
	encryptString, err := cfb.Encrypt([]byte("123456"))
	if err != nil {
		t.Error("encrypt error", err)
	}
	t.Log(encryptString)

	decryptString, err := cfb.Decrypt(encryptString)
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

func TestSha256(t *testing.T) {
	key := "IgkibX71IEf382PT" //
	keyb := sha256.Sum256([]byte(key))
	t.Log("key:", key, " len:", len(key))
	fmt.Println("keyb:", string(keyb[:]), " len:", len(string(keyb[:])))
}
