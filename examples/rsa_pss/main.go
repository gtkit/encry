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

	dir, err := os.MkdirTemp("", "encry-rsa-pss-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err = rsa.GenerateRsaKey(2048, dir); err != nil {
		return err
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")

	signature, err := rsa.SignPSSBase64([]byte("hello-pss"), privateKeyPath)
	if err != nil {
		return err
	}

	if err := rsa.VerifyPSSBase64([]byte("hello-pss"), publicKeyPath, signature); err != nil {
		return err
	}

	out.Println("signature:", signature)
	out.Println("verify:", true)
	return nil
}
