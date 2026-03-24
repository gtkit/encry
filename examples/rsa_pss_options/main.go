package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"path/filepath"

	encryrsa "github.com/gtkit/encry/rsa"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-rsa-pss-options-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	if err := encryrsa.GenerateRsaKey(2048, dir); err != nil {
		log.Fatal(err)
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA512,
	}

	signature, err := encryrsa.SignPSSBase64WithOptions([]byte("settlement-report"), privateKeyPath, crypto.SHA512, opts)
	if err != nil {
		log.Fatal(err)
	}

	if err := encryrsa.VerifyPSSBase64WithOptions([]byte("settlement-report"), publicKeyPath, signature, crypto.SHA512, opts); err != nil {
		log.Fatal(err)
	}

	verifyErr := encryrsa.VerifyPSSBase64WithOptions([]byte("settlement-report"), publicKeyPath, signature, crypto.SHA256, nil)

	fmt.Println("signature:", signature)
	fmt.Println("verify:", true)
	fmt.Println("wrong options rejected:", verifyErr != nil)
}
