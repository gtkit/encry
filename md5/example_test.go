package md5_test

import (
	"fmt"

	encrymd5 "github.com/gtkit/encry/md5"
)

func ExampleString() {
	fmt.Println(encrymd5.String("hello"))
	// Output: 5d41402abc4b2a76b9719d911017c592
}
