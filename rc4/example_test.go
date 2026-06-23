package rc4_test

import (
	"fmt"

	"github.com/gtkit/encry/rc4"
)

func ExampleEncryptStringToBase64() {
	const key = "secret-key"
	enc, err := rc4.EncryptStringToBase64(key, "hello-rc4")
	if err != nil {
		panic(err)
	}
	dec, err := rc4.DecryptBase64ToString(key, enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(dec)
	// Output: hello-rc4
}
