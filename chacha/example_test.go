package chacha_test

import (
	"fmt"

	"github.com/gtkit/encry/chacha"
)

func ExampleChaCha() {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 字节
	c, err := chacha.NewChaCha(key)
	if err != nil {
		panic(err)
	}

	enc, err := c.Encrypt([]byte("hello"))
	if err != nil {
		panic(err)
	}

	got, err := c.Decrypt(enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(got))
	// Output: hello
}
