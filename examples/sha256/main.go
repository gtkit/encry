package main

import (
	"log"
	"os"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func main() {
	run(nil)
}

func run(out *log.Logger) {
	if out == nil {
		out = log.New(os.Stdout, "", 0)
	}
	text := "hello-sha"

	out.Println("sha224:", encrysha256.String224(text))
	out.Println("sha256:", encrysha256.String(text))
	out.Println("sha384:", encrysha256.String384(text))
	out.Println("sha512:", encrysha256.String512(text))
}
