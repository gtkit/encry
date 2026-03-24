package main

import (
	"fmt"
	"log"

	"github.com/gtkit/encry/aes"
)

func main() {
	gcm := aes.NewGCM("IgkibX71IEf382PT")
	aad := []byte("order:1001")

	cipherText, err := gcm.EncryptWithAAD([]byte("hello-gcm"), aad)
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, aad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("cipher:", cipherText)
	fmt.Println("plain:", string(plainText))
}
