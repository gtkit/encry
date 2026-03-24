package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/ed"
)

func main() {
	baseDir, err := os.MkdirTemp("", "encry-ed25519-files-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	// 模拟业务里常见的密钥存储结构。
	keyDir := filepath.Join(baseDir, "keys", "ed25519")
	privateKeyPath := filepath.Join(keyDir, "private.pem")
	publicKeyPath := filepath.Join(keyDir, "public.pem")

	if err := ed.WriteKeyPair(privateKeyPath, publicKeyPath); err != nil {
		log.Fatal(err)
	}

	signature, err := ed.SignFileBase64([]byte("customer-export"), privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := ed.VerifyFileBase64([]byte("customer-export"), publicKeyPath, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("key dir:", keyDir)
	fmt.Println("private key:", privateKeyPath)
	fmt.Println("public key:", publicKeyPath)
	fmt.Println("verify:", ok)
}
