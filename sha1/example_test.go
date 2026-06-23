package sha1_test

import (
	"fmt"

	encrysha1 "github.com/gtkit/encry/sha1"
)

func ExampleString() {
	fmt.Println(encrysha1.String("hello"))
	// Output: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
}
