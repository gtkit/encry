package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gtkit/encry/examples/internal/cryptoenv"
	"github.com/gtkit/encry/internal/keyring"
	"github.com/gtkit/encry/internal/sealer"
	json "github.com/gtkit/json"
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

	cfg, cleanup, err := cryptoenv.LoadKeyConfig(
		"ENCRY_AES_KEY_DIR",
		"ENCRY_AES_ACTIVE_KID",
		"encry-service-aes-*",
		filepath.Join("keys", "aes"),
		"2026-03",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := ensureAESDemoKeys(cfg.KeyDir, "2026-03", "2026-04"); err != nil {
		return err
	}

	ring := keyring.New[keyring.Record[string]]()
	if err := reloadAESKeys(ring, cfg.KeyDir, cfg.ActiveKID); err != nil {
		return err
	}
	service := sealer.NewManagedAESGCM(ring)

	aad := []byte("tenant=acme;scene=checkout")
	tokenV1, err := service.Encrypt([]byte(`{"order_id":"1001","status":"paid"}`), aad)
	if err != nil {
		return err
	}

	if err := writeAESMetadata(cfg.KeyDir, "2026-03", keyring.StatusRetiring); err != nil {
		return err
	}
	if err := reloadAESKeys(ring, cfg.KeyDir, "2026-04"); err != nil {
		return err
	}
	tokenV2, err := service.Encrypt([]byte(`{"order_id":"1002","status":"paid"}`), aad)
	if err != nil {
		return err
	}

	plainV1, err := service.Decrypt(tokenV1, aad)
	if err != nil {
		return err
	}
	plainV2, err := service.Decrypt(tokenV2, aad)
	if err != nil {
		return err
	}

	_, wrongAADErr := service.Decrypt(tokenV2, []byte("tenant=acme;scene=refund"))

	snapshot, err := ring.Current()
	if err != nil {
		return err
	}

	out.Println("active kid:", snapshot.ActiveKID)
	out.Println("token v1 generated:", tokenV1 != "")
	out.Println("token v2 generated:", tokenV2 != "")
	out.Println("decrypt v1 ok:", len(plainV1) > 0)
	out.Println("decrypt v2 ok:", len(plainV2) > 0)
	out.Println("wrong aad rejected:", wrongAADErr != nil)
	return nil
}

func ensureAESDemoKeys(keyDir string, kids ...string) error {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return err
	}
	for _, kid := range kids {
		path := filepath.Join(keyDir, kid+".key")
		if _, err := os.Stat(path); err == nil {
			continue
		}

		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		key := base64.RawURLEncoding.EncodeToString(raw) // 24 bytes -> 32 chars, 可直接作为 AES-256 key
		if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
			return err
		}
		if err := writeAESMetadata(keyDir, kid, keyring.StatusActive); err != nil {
			return err
		}
	}
	return nil
}

func reloadAESKeys(ring *keyring.Ring[keyring.Record[string]], keyDir, activeKID string) error {
	keys, err := keyring.LoadStringKeyRecords(keyDir, ".key", "A256GCM", "enc")
	if err != nil {
		return err
	}
	return ring.Store(activeKID, keys)
}

func writeAESMetadata(keyDir, kid string, status keyring.KeyStatus) error {
	metadata := keyring.Metadata{
		KID:       kid,
		Algorithm: "A256GCM",
		Use:       "enc",
		Status:    status,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		NotBefore: time.Now().Add(-90 * time.Minute),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(keyDir, kid+".json"), raw, 0o600)
}
