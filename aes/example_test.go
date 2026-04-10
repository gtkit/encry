package aes_test

import (
	"log"
	"os"

	"github.com/gtkit/encry/aes"
)

func ExampleNewGCM() {
	out := log.New(os.Stdout, "", 0)
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.Encrypt([]byte("hello-gcm"))
	if err != nil {
		panic(err)
	}

	plainText, err := gcm.Decrypt(cipherText)
	if err != nil {
		panic(err)
	}

	out.Println(plainText)
	// Output:
	// hello-gcm
}

func ExampleGCM_EncryptWithAAD() {
	out := log.New(os.Stdout, "", 0)
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.EncryptWithAAD([]byte("hello-gcm"), []byte("aad"))
	if err != nil {
		panic(err)
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, []byte("aad"))
	if err != nil {
		panic(err)
	}

	out.Println(string(plainText))
	// Output:
	// hello-gcm
}
