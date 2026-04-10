package main

import (
	"log"
	"os"

	"github.com/gtkit/encry/aes"
)

func main() {
	if err := run(nil); err != nil {
		log.Fatal(err)
	}
}

func run(out *log.Logger) error {
	if out == nil {
		out = log.New(os.Stdout, "", 0)
	}

	gcm := aes.NewGCM("IgkibX71IEf382PT")
	aad := []byte("order:1001")

	cipherText, err := gcm.EncryptWithAAD([]byte("hello-gcm"), aad)
	if err != nil {
		return err
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, aad)
	if err != nil {
		return err
	}

	out.Println("cipher:", cipherText)
	out.Println("plain:", string(plainText))
	return nil
}
