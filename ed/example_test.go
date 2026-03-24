package ed_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/ed"
)

func ExampleGenerateKeyPair() {
	publicKey, privateKey, err := ed.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	signature, err := ed.SignBase64(privateKey, []byte("hello-ed25519"))
	if err != nil {
		panic(err)
	}

	fmt.Println(ed.VerifyBase64(publicKey, []byte("hello-ed25519"), signature))
	// Output:
	// true
}

func ExampleWriteKeyPair() {
	dir, err := os.MkdirTemp("", "encry-ed25519-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	if err := ed.WriteKeyPair(privatePath, publicPath); err != nil {
		panic(err)
	}

	signature, err := ed.SignFileBase64([]byte("hello-ed25519"), privatePath)
	if err != nil {
		panic(err)
	}

	ok, err := ed.VerifyFileBase64([]byte("hello-ed25519"), publicPath, signature)
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	// Output:
	// true
}
