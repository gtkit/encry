package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/ed"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-ed25519-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	privateKeyPath := filepath.Join(dir, "private.pem")
	publicKeyPath := filepath.Join(dir, "public.pem")

	if err := ed.WriteKeyPair(privateKeyPath, publicKeyPath); err != nil {
		log.Fatal(err)
	}

	signature, err := ed.SignFileBase64([]byte("hello-ed25519"), privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := ed.VerifyFileBase64([]byte("hello-ed25519"), publicKeyPath, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature:", signature)
	fmt.Println("verify:", ok)
}
