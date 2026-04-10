package sha256_test

import (
	"log"
	"os"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func ExampleString() {
	log.New(os.Stdout, "", 0).Println(encrysha256.String("hello"))
	// Output:
	// 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
}

func ExampleString512() {
	log.New(os.Stdout, "", 0).Println(len(encrysha256.String512("hello")))
	// Output:
	// 128
}
