package base64_test

import (
	"fmt"

	encrybase64 "github.com/gtkit/encry/base64"
)

func ExampleStdEncode() {
	fmt.Println(encrybase64.StdEncode([]byte("hello")))
	// Output: aGVsbG8=
}
