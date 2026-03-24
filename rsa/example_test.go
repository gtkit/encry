package rsa_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gtkit/encry/rsa"
)

func ExampleEncryptOAEPBase64() {
	dir, err := os.MkdirTemp("", "encry-rsa-oaep-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	if err := rsa.GenerateRsaKey(2048, dir); err != nil {
		panic(err)
	}

	cipherText, err := rsa.EncryptOAEPBase64([]byte("hello-oaep"), filepath.Join(dir, "public.pem"))
	if err != nil {
		panic(err)
	}

	plainText, err := rsa.DecryptOAEPBase64(cipherText, filepath.Join(dir, "private.pem"))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plainText))
	// Output:
	// hello-oaep
}

func ExampleSignPSSBase64() {
	dir, err := os.MkdirTemp("", "encry-rsa-pss-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	if err := rsa.GenerateRsaKey(2048, dir); err != nil {
		panic(err)
	}

	signature, err := rsa.SignPSSBase64([]byte("hello-pss"), filepath.Join(dir, "private.pem"))
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPSSBase64([]byte("hello-pss"), filepath.Join(dir, "public.pem"), signature)
	fmt.Println(err == nil)
	// Output:
	// true
}
