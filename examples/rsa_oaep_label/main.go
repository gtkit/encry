package main

import (
	"crypto"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/rsa"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-rsa-oaep-label-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	if err := rsa.GenerateRsaKey(2048, dir); err != nil {
		log.Fatal(err)
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")
	label := []byte("scene:invoice-export:v1")

	cipherText, err := rsa.EncryptOAEPBase64WithOptions([]byte("invoice-1001"), publicKeyPath, crypto.SHA512, label)
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := rsa.DecryptOAEPBase64WithOptions(cipherText, privateKeyPath, crypto.SHA512, label)
	if err != nil {
		log.Fatal(err)
	}

	_, wrongLabelErr := rsa.DecryptOAEPBase64WithOptions(cipherText, privateKeyPath, crypto.SHA512, []byte("scene:invoice-export:v2"))

	fmt.Println("cipher:", cipherText)
	fmt.Println("plain:", string(plainText))
	fmt.Println("wrong label rejected:", wrongLabelErr != nil)
}
