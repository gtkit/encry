package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/rsa"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-rsa-pss-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	if err := rsa.GenerateRsaKey(2048, dir); err != nil {
		log.Fatal(err)
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")

	signature, err := rsa.SignPSSBase64([]byte("hello-pss"), privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := rsa.VerifyPSSBase64([]byte("hello-pss"), publicKeyPath, signature); err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature:", signature)
	fmt.Println("verify:", true)
}
