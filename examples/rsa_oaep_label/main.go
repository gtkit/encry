package main

import (
	"crypto"
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/rsa"
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

	dir, err := os.MkdirTemp("", "encry-rsa-oaep-label-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err := rsa.GenerateRsaKey(2048, dir); err != nil {
		return err
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")
	label := []byte("scene:invoice-export:v1")

	cipherText, err := rsa.EncryptOAEPBase64WithOptions([]byte("invoice-1001"), publicKeyPath, crypto.SHA512, label)
	if err != nil {
		return err
	}

	plainText, err := rsa.DecryptOAEPBase64WithOptions(cipherText, privateKeyPath, crypto.SHA512, label)
	if err != nil {
		return err
	}

	_, wrongLabelErr := rsa.DecryptOAEPBase64WithOptions(cipherText, privateKeyPath, crypto.SHA512, []byte("scene:invoice-export:v2"))

	out.Println("cipher:", cipherText)
	out.Println("plain:", string(plainText))
	out.Println("wrong label rejected:", wrongLabelErr != nil)
	return nil
}
