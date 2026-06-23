package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/examples/internal/cryptoenv"
	"github.com/gtkit/encry/internal/keyring"
	"github.com/gtkit/encry/internal/signer"
	json "github.com/gtkit/json/v2"
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
		"ENCRY_ED25519_KEY_DIR",
		"ENCRY_ED25519_ACTIVE_KID",
		"encry-service-ed25519-*",
		filepath.Join("keys", "ed25519"),
		"2026-03",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	if err = ensureDemoKeys(cfg.KeyDir, "2026-03", "2026-04"); err != nil {
		return err
	}

	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	if err = reloadEd25519Keys(ring, cfg.KeyDir, cfg.ActiveKID); err != nil {
		return err
	}
	service := signer.NewManagedEd25519(ring)

	signatureV1, err := service.Sign([]byte(`{"event":"user.created","id":"1001"}`))
	if err != nil {
		return err
	}

	if err = writeEd25519Metadata(cfg.KeyDir, "2026-03", keyring.StatusRetiring); err != nil {
		return err
	}
	if err = reloadEd25519Keys(ring, cfg.KeyDir, "2026-04"); err != nil {
		return err
	}
	signatureV2, err := service.Sign([]byte(`{"event":"user.updated","id":"1001"}`))
	if err != nil {
		return err
	}

	okV1, err := service.Verify([]byte(`{"event":"user.created","id":"1001"}`), signatureV1)
	if err != nil {
		return err
	}
	okV2, err := service.Verify([]byte(`{"event":"user.updated","id":"1001"}`), signatureV2)
	if err != nil {
		return err
	}
	wrongPayloadOK, err := service.Verify([]byte(`{"event":"user.deleted","id":"1001"}`), signatureV2)
	if err != nil {
		return err
	}

	snapshot, err := ring.Current()
	if err != nil {
		return err
	}

	out.Println("key dir:", cfg.KeyDir)
	out.Println("active kid:", snapshot.ActiveKID)
	out.Println("signature v1:", signatureV1)
	out.Println("signature v2:", signatureV2)
	out.Println("verify v1:", okV1)
	out.Println("verify v2:", okV2)
	out.Println("wrong payload rejected:", !wrongPayloadOK)
	return nil
}

func ensureDemoKeys(keyDir string, kids ...string) error {
	for _, kid := range kids {
		privatePath := filepath.Join(keyDir, kid, "private.pem")
		publicPath := filepath.Join(keyDir, kid, "public.pem")
		if _, err := os.Stat(privatePath); err == nil {
			continue
		}
		if err := ed.WriteKeyPair(privatePath, publicPath); err != nil {
			return err
		}
		if err := writeEd25519Metadata(keyDir, kid, keyring.StatusActive); err != nil {
			return err
		}
	}
	return nil
}

func reloadEd25519Keys(ring *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]], keyDir, activeKID string) error {
	keys, err := keyring.LoadEd25519KeyPairRecords(keyDir)
	if err != nil {
		return err
	}
	return ring.Store(activeKID, keys)
}

func writeEd25519Metadata(keyDir, kid string, status keyring.KeyStatus) error {
	metadata := keyring.Metadata{
		KID:       kid,
		Algorithm: "EdDSA",
		Use:       "sig",
		Status:    status,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		NotBefore: time.Now().Add(-90 * time.Minute),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(keyDir, kid, "metadata.json"), raw, 0o600)
}
