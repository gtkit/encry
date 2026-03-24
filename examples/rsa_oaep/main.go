package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/rsa"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-rsa-oaep-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	if err := rsa.GenerateRsaKey(2048, dir); err != nil {
		log.Fatal(err)
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")

	cipherText, err := rsa.EncryptOAEPBase64([]byte("hello-oaep"), publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := rsa.DecryptOAEPBase64(cipherText, privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("cipher:", cipherText)
	fmt.Println("plain:", string(plainText))
}
