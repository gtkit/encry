package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-sha256-file-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(path, []byte(`{"order_id":"1001","status":"paid"}`), 0o600); err != nil {
		log.Fatal(err)
	}

	sum, err := encrysha256.File(path)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("file:", path)
	fmt.Println("sha256:", sum)
	fmt.Println("verify:", encrysha256.VerifyString(`{"order_id":"1001","status":"paid"}`, sum))
}
