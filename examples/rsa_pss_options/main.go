package main

import (
	"crypto"
	"crypto/rsa"
	"log"
	"os"
	"path/filepath"

	encryrsa "github.com/gtkit/encry/rsa"
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

	dir, err := os.MkdirTemp("", "encry-rsa-pss-options-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err = encryrsa.GenerateRsaKey(2048, dir); err != nil {
		return err
	}

	publicKeyPath := filepath.Join(dir, "public.pem")
	privateKeyPath := filepath.Join(dir, "private.pem")
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA512,
	}

	signature, err := encryrsa.SignPSSBase64WithOptions([]byte("settlement-report"), privateKeyPath, crypto.SHA512, opts)
	if err != nil {
		return err
	}

	ok, err := encryrsa.VerifyPSSBase64WithOptions([]byte("settlement-report"), publicKeyPath, signature, crypto.SHA512, opts)
	if err != nil {
		return err
	}

	wrongOK, _ := encryrsa.VerifyPSSBase64WithOptions([]byte("settlement-report"), publicKeyPath, signature, crypto.SHA256, nil)

	out.Println("signature:", signature)
	out.Println("verify:", ok)
	out.Println("wrong options rejected:", !wrongOK)
	return nil
}
