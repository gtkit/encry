package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/ed"
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

	dir, err := os.MkdirTemp("", "encry-ed25519-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	privateKeyPath := filepath.Join(dir, "private.pem")
	publicKeyPath := filepath.Join(dir, "public.pem")

	if err = ed.WriteKeyPair(privateKeyPath, publicKeyPath); err != nil {
		return err
	}

	signature, err := ed.SignFileBase64([]byte("hello-ed25519"), privateKeyPath)
	if err != nil {
		return err
	}

	ok, err := ed.VerifyFileBase64([]byte("hello-ed25519"), publicKeyPath, signature)
	if err != nil {
		return err
	}

	out.Println("signature:", signature)
	out.Println("verify:", ok)
	return nil
}
