package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/cryptoenv"
	"github.com/gtkit/encry/internal/keyring"
	"github.com/gtkit/encry/internal/middleware"
	"github.com/gtkit/encry/internal/signer"
)

func main() {
	cfg, cleanup, err := cryptoenv.LoadKeyConfig(
		"ENCRY_HTTP_ED25519_KEY_DIR",
		"ENCRY_HTTP_ED25519_ACTIVE_KID",
		"encry-http-middleware-*",
		filepath.Join("keys", "ed25519"),
		"2026-03",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	if err := ensureEdKeys(cfg.KeyDir, "2026-03", keyring.StatusActive); err != nil {
		log.Fatal(err)
	}

	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	records, err := keyring.LoadEd25519KeyPairRecords(cfg.KeyDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := ring.Store(cfg.ActiveKID, records); err != nil {
		log.Fatal(err)
	}
	service := signer.NewManagedEd25519(ring)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /callbacks/order-paid", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("accepted"))
	})

	handler := middleware.HTTPVerifyMiddleware(service)(mux)

	validBody := []byte(`{"order_id":"1001","status":"paid"}`)
	validSignature, err := service.Sign(validBody)
	if err != nil {
		log.Fatal(err)
	}

	validReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	validReq.Header.Set("X-Signature", validSignature)
	validResp := httptest.NewRecorder()
	handler.ServeHTTP(validResp, validReq)

	invalidReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	invalidReq.Header.Set("X-Signature", "2026-03.invalid-signature")
	invalidResp := httptest.NewRecorder()
	handler.ServeHTTP(invalidResp, invalidReq)

	fmt.Println("valid status:", validResp.Code)
	fmt.Println("valid body:", validResp.Body.String())
	fmt.Println("invalid status:", invalidResp.Code)
}

func ensureEdKeys(root, kid string, status keyring.KeyStatus) error {
	privatePath := filepath.Join(root, kid, "private.pem")
	publicPath := filepath.Join(root, kid, "public.pem")
	if err := ed.WriteKeyPair(privatePath, publicPath); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(keyring.Metadata{
		KID:       kid,
		Algorithm: "EdDSA",
		Use:       "sig",
		Status:    status,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		NotBefore: time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, kid, "metadata.json"), raw, 0o600)
}
