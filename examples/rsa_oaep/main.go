package main

import (
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

	dir, err := os.MkdirTemp("", "encry-rsa-oaep-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err = rsa.GenerateRsaKey(2048, dir); err != nil {
		return err
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")

	cipherText, err := rsa.EncryptOAEPBase64([]byte("hello-oaep"), publicKeyPath)
	if err != nil {
		return err
	}

	plainText, err := rsa.DecryptOAEPBase64(cipherText, privateKeyPath)
	if err != nil {
		return err
	}

	out.Println("cipher:", cipherText)
	out.Println("plain:", string(plainText))
	return nil
}
