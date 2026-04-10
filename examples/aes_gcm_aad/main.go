package main

import (
	"log"
	"os"

	"github.com/gtkit/encry/aes"
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

	gcm := aes.NewGCM("IgkibX71IEf382PT")

	// 业务上把订单上下文作为 AAD，确保密文只能在对应上下文中被接受。
	aad := []byte("tenant=acme;order=1001;scene=payment")

	cipherText, err := gcm.EncryptWithAAD([]byte(`{"amount":199,"currency":"CNY"}`), aad)
	if err != nil {
		return err
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, aad)
	if err != nil {
		return err
	}

	_, tamperErr := gcm.DecryptWithAAD(cipherText, []byte("tenant=acme;order=1002;scene=payment"))

	out.Println("cipher:", cipherText)
	out.Println("plain:", string(plainText))
	out.Println("wrong aad rejected:", tamperErr != nil)
	return nil
}
