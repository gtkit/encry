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

	baseDir, err := os.MkdirTemp("", "encry-ed25519-files-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(baseDir)

	// 模拟业务里常见的密钥存储结构。
	keyDir := filepath.Join(baseDir, "keys", "ed25519")
	privateKeyPath := filepath.Join(keyDir, "private.pem")
	publicKeyPath := filepath.Join(keyDir, "public.pem")

	if err := ed.WriteKeyPair(privateKeyPath, publicKeyPath); err != nil {
		return err
	}

	signature, err := ed.SignFileBase64([]byte("customer-export"), privateKeyPath)
	if err != nil {
		return err
	}

	ok, err := ed.VerifyFileBase64([]byte("customer-export"), publicKeyPath, signature)
	if err != nil {
		return err
	}

	out.Println("key dir:", keyDir)
	out.Println("private key written:", privateKeyPath != "")
	out.Println("public key written:", publicKeyPath != "")
	out.Println("verify:", ok)
	return nil
}
