package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/keyring"
	encryrsa "github.com/gtkit/encry/rsa"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-jwks-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	edDir := filepath.Join(dir, "ed25519")
	rsaDir := filepath.Join(dir, "rsa")
	if err := ensureEdKeys(edDir, "ed-active", keyring.StatusActive, false); err != nil {
		log.Fatal(err)
	}
	if err := ensureEdKeys(edDir, "ed-revoked", keyring.StatusRevoked, true); err != nil {
		log.Fatal(err)
	}
	if err := ensureRSAKeys(rsaDir, "rsa-active", keyring.StatusActive, false); err != nil {
		log.Fatal(err)
	}
	if err := ensureRSAKeys(rsaDir, "rsa-retiring", keyring.StatusRetiring, false); err != nil {
		log.Fatal(err)
	}

	edRing := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	edRecords, err := keyring.LoadEd25519KeyPairRecords(edDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := edRing.Store("ed-active", edRecords); err != nil {
		log.Fatal(err)
	}
	edSnapshot, err := edRing.Current()
	if err != nil {
		log.Fatal(err)
	}

	rsaRing := keyring.New[keyring.Record[keyring.RSAKeyPair]]()
	rsaRecords, err := keyring.LoadRSAKeyPairRecords(rsaDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := rsaRing.Store("rsa-active", rsaRecords); err != nil {
		log.Fatal(err)
	}
	rsaSnapshot, err := rsaRing.Current()
	if err != nil {
		log.Fatal(err)
	}

	edJWK, err := keyring.Ed25519PublicJWKSet(edSnapshot).JSON()
	if err != nil {
		log.Fatal(err)
	}
	rsaJWK, err := keyring.RSAPublicJWKSet(rsaSnapshot).JSON()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("ed25519 jwks:")
	fmt.Println(string(edJWK))
	fmt.Println("rsa jwks:")
	fmt.Println(string(rsaJWK))
}

func ensureEdKeys(root, kid string, status keyring.KeyStatus, revoked bool) error {
	privatePath := filepath.Join(root, kid, "private.pem")
	publicPath := filepath.Join(root, kid, "public.pem")
	if err := ed.WriteKeyPair(privatePath, publicPath); err != nil {
		return err
	}
	return writeMetadata(filepath.Join(root, kid, "metadata.json"), keyring.Metadata{
		KID:       kid,
		Algorithm: "EdDSA",
		Use:       "sig",
		Status:    status,
		CreatedAt: time.Now().Add(-48 * time.Hour),
		NotBefore: time.Now().Add(-24 * time.Hour),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RevokedAt: cmpRevokedAt(revoked),
	})
}

func ensureRSAKeys(root, kid string, status keyring.KeyStatus, revoked bool) error {
	if err := encryrsa.GenerateRsaKey(2048, filepath.Join(root, kid)); err != nil {
		return err
	}
	return writeMetadata(filepath.Join(root, kid, "metadata.json"), keyring.Metadata{
		KID:       kid,
		Algorithm: "PS512",
		Use:       "sig",
		Status:    status,
		CreatedAt: time.Now().Add(-48 * time.Hour),
		NotBefore: time.Now().Add(-24 * time.Hour),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RevokedAt: cmpRevokedAt(revoked),
	})
}

func writeMetadata(path string, metadata keyring.Metadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func cmpRevokedAt(revoked bool) time.Time {
	if revoked {
		return time.Now().Add(-time.Hour)
	}
	return time.Time{}
}
