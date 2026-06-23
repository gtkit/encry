package main

import (
	"log"
	"os"
	"path/filepath"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func main() {
	if err := run(nil); err != nil {
		log.Fatal(err)
	}
}

func run(out *log.Logger) error {
	if out == nil {
		out = log.New(os.Stdout, "", 0)
	}

	dir, err := os.MkdirTemp("", "encry-sha256-file-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "payload.json")
	if err = os.WriteFile(path, []byte(`{"order_id":"1001","status":"paid"}`), 0o600); err != nil {
		return err
	}

	sum, err := encrysha256.File(path)
	if err != nil {
		return err
	}

	out.Println("file:", path)
	out.Println("sha256:", sum)
	out.Println("verify:", encrysha256.VerifyString(`{"order_id":"1001","status":"paid"}`, sum))
	return nil
}
