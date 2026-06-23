package main

import (
	"crypto"
	stdrsa "crypto/rsa"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gtkit/encry/examples/internal/cryptoenv"
	"github.com/gtkit/encry/internal/keyring"
	"github.com/gtkit/encry/internal/signer"
	encryrsa "github.com/gtkit/encry/rsa"
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
		"ENCRY_RSA_PSS_KEY_DIR",
		"ENCRY_RSA_PSS_ACTIVE_KID",
		"encry-service-rsa-pss-*",
		filepath.Join("keys", "rsa_pss"),
		"2026-03",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	if err = ensureDemoKeys(cfg.KeyDir, "2026-03", "2026-04"); err != nil {
		return err
	}

	ring := keyring.New[keyring.Record[keyring.RSAKeyPair]]()
	if err = reloadRSAKeys(ring, cfg.KeyDir, cfg.ActiveKID); err != nil {
		return err
	}
	opts := &stdrsa.PSSOptions{
		SaltLength: stdrsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA512,
	}
	service := signer.NewManagedRSAPSS(ring, crypto.SHA512, opts)

	signatureV1, err := service.Sign([]byte(`{"report":"settlement","batch":"2026-03-24"}`))
	if err != nil {
		return err
	}

	if err = writeRSAMetadata(cfg.KeyDir, "2026-03", keyring.StatusRetiring); err != nil {
		return err
	}
	if err = reloadRSAKeys(ring, cfg.KeyDir, "2026-04"); err != nil {
		return err
	}
	signatureV2, err := service.Sign([]byte(`{"report":"settlement","batch":"2026-04-01"}`))
	if err != nil {
		return err
	}

	okV1, err := service.Verify([]byte(`{"report":"settlement","batch":"2026-03-24"}`), signatureV1)
	if err != nil {
		return err
	}
	okV2, err := service.Verify([]byte(`{"report":"settlement","batch":"2026-04-01"}`), signatureV2)
	if err != nil {
		return err
	}
	wrongHashOK, err := service.VerifyWith([]byte(`{"report":"settlement","batch":"2026-04-01"}`), signatureV2, crypto.SHA256, nil)
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
	out.Println("wrong options rejected:", !wrongHashOK)
	return nil
}

func ensureDemoKeys(keyDir string, kids ...string) error {
	for _, kid := range kids {
		dir := filepath.Join(keyDir, kid)
		if _, err := os.Stat(filepath.Join(dir, "private.pem")); err == nil {
			continue
		}
		if err := encryrsa.GenerateRsaKey(2048, dir); err != nil {
			return err
		}
		if err := writeRSAMetadata(keyDir, kid, keyring.StatusActive); err != nil {
			return err
		}
	}
	return nil
}

func reloadRSAKeys(ring *keyring.Ring[keyring.Record[keyring.RSAKeyPair]], keyDir, activeKID string) error {
	keys, err := keyring.LoadRSAKeyPairRecords(keyDir)
	if err != nil {
		return err
	}
	return ring.Store(activeKID, keys)
}

func writeRSAMetadata(keyDir, kid string, status keyring.KeyStatus) error {
	metadata := keyring.Metadata{
		KID:       kid,
		Algorithm: "PS512",
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
