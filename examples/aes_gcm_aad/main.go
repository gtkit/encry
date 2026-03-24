package main

import (
	"fmt"
	"log"

	"github.com/gtkit/encry/aes"
)

func main() {
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	// 业务上把订单上下文作为 AAD，确保密文只能在对应上下文中被接受。
	aad := []byte("tenant=acme;order=1001;scene=payment")

	cipherText, err := gcm.EncryptWithAAD([]byte(`{"amount":199,"currency":"CNY"}`), aad)
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, aad)
	if err != nil {
		log.Fatal(err)
	}

	_, tamperErr := gcm.DecryptWithAAD(cipherText, []byte("tenant=acme;order=1002;scene=payment"))

	fmt.Println("cipher:", cipherText)
	fmt.Println("plain:", string(plainText))
	fmt.Println("wrong aad rejected:", tamperErr != nil)
}
