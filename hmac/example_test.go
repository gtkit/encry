package hmac_test

import (
	"fmt"

	encryhmac "github.com/gtkit/encry/hmac"
)

func ExampleSha256Verify() {
	key := []byte("secret")
	data := []byte("payload")
	sig := encryhmac.Sha256ToHex(key, data)
	fmt.Println(encryhmac.Sha256Verify(string(key), string(data), sig))
	// Output: true
}
