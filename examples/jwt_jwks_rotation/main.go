package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/jwtauth"
	"github.com/gtkit/encry/internal/keyring"
	jwtclaims "github.com/gtkit/encry/jwt/claims"
)

func main() {
	dir, err := os.MkdirTemp("", "encry-jwt-jwks-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	keyDir := filepath.Join(dir, "keys", "ed25519")
	if err := ensureEdKey(keyDir, "2026-03", keyring.StatusActive, false); err != nil {
		log.Fatal(err)
	}
	if err := ensureEdKey(keyDir, "2026-04", keyring.StatusActive, false); err != nil {
		log.Fatal(err)
	}

	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	if err := reloadJWTKeys(ring, keyDir, "2026-03"); err != nil {
		log.Fatal(err)
	}

	service := jwtauth.NewEd25519(
		ring,
		jwtauth.WithTokenDuration(10*time.Minute),
		jwtauth.WithParserOptions(
			gojwt.WithIssuer("acme-api"),
			gojwt.WithAudience("payments"),
		),
	)

	tokenV1, err := service.Issue(1001,
		jwtclaims.WithIssuer("acme-api"),
		jwtclaims.WithAudience("payments"),
		jwtclaims.WithRoles("payer"),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := writeMetadata(filepath.Join(keyDir, "2026-03", "metadata.json"), keyring.Metadata{
		KID:       "2026-03",
		Algorithm: "EdDSA",
		Use:       "sig",
		Status:    keyring.StatusRetiring,
		CreatedAt: time.Now().Add(-48 * time.Hour),
		NotBefore: time.Now().Add(-24 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		log.Fatal(err)
	}
	if err := reloadJWTKeys(ring, keyDir, "2026-04"); err != nil {
		log.Fatal(err)
	}

	tokenV2, err := service.Issue(1002,
		jwtclaims.WithIssuer("acme-api"),
		jwtclaims.WithAudience("payments"),
		jwtclaims.WithRoles("payer", "refund"),
	)
	if err != nil {
		log.Fatal(err)
	}

	claimsV1, err := service.Parse(tokenV1)
	if err != nil {
		log.Fatal(err)
	}
	claimsV2, err := service.Parse(tokenV2)
	if err != nil {
		log.Fatal(err)
	}

	jwks, err := service.JWKS()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("active kid:", "2026-04")
	fmt.Println("token v1 uid:", claimsV1.UserID)
	fmt.Println("token v2 uid:", claimsV2.UserID)
	fmt.Println("jwks keys:", len(jwks.Keys))
	fmt.Println("jwks first alg:", jwks.Keys[0].Alg)
}

func ensureEdKey(root, kid string, status keyring.KeyStatus, revoked bool) error {
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
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RevokedAt: revokedAt(revoked),
	})
}

func reloadJWTKeys(ring *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]], dir, activeKID string) error {
	keys, err := keyring.LoadEd25519KeyPairRecords(dir)
	if err != nil {
		return err
	}
	return ring.Store(activeKID, keys)
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

func revokedAt(revoked bool) time.Time {
	if revoked {
		return time.Now().Add(-time.Minute)
	}
	return time.Time{}
}
