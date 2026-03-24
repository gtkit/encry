package main

import (
	"fmt"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func main() {
	text := "hello-sha"

	fmt.Println("sha224:", encrysha256.String224(text))
	fmt.Println("sha256:", encrysha256.String(text))
	fmt.Println("sha384:", encrysha256.String384(text))
	fmt.Println("sha512:", encrysha256.String512(text))
}
