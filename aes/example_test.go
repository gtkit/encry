package aes_test

import (
	"fmt"

	"github.com/gtkit/encry/aes"
)

func ExampleNewGCM() {
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.Encrypt([]byte("hello-gcm"))
	if err != nil {
		panic(err)
	}

	plainText, err := gcm.Decrypt(cipherText)
	if err != nil {
		panic(err)
	}

	fmt.Println(plainText)
	// Output:
	// hello-gcm
}

func ExampleGCM_EncryptWithAAD() {
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.EncryptWithAAD([]byte("hello-gcm"), []byte("aad"))
	if err != nil {
		panic(err)
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, []byte("aad"))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plainText))
	// Output:
	// hello-gcm
}
