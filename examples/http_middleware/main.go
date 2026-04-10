package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/examples/internal/cryptoenv"
	"github.com/gtkit/encry/internal/httpsig"
	"github.com/gtkit/encry/internal/keyring"
	"github.com/gtkit/encry/internal/middleware"
	"github.com/gtkit/encry/internal/signer"
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
		"ENCRY_HTTP_ED25519_KEY_DIR",
		"ENCRY_HTTP_ED25519_ACTIVE_KID",
		"encry-http-middleware-*",
		filepath.Join("keys", "ed25519"),
		"2026-03",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := ensureEdKeys(cfg.KeyDir, "2026-03", keyring.StatusActive); err != nil {
		return err
	}

	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	records, err := keyring.LoadEd25519KeyPairRecords(cfg.KeyDir)
	if err != nil {
		return err
	}
	if err := ring.Store(cfg.ActiveKID, records); err != nil {
		return err
	}
	service := signer.NewManagedEd25519(ring)
	nonceStore := httpsig.NewMemoryNonceStore()
	verifyOpts := httpsig.VerifyOptions{
		MaxSkew:      5 * time.Minute,
		Nonces:       nonceStore,
		MaxBodyBytes: 1 << 20,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /callbacks/order-paid", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("accepted"))
	})

	handler := middleware.HTTPVerifyRequestMiddleware(service, verifyOpts)(mux)

	validBody := []byte(`{"order_id":"1001","status":"paid"}`)
	validHeaders, err := httpsig.SignRequest(service, http.MethodPost, "/callbacks/order-paid", "", validBody, time.Now(), "nonce-1001")
	if err != nil {
		return err
	}

	validReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	validHeaders.Apply(validReq.Header)
	validResp := httptest.NewRecorder()
	handler.ServeHTTP(validResp, validReq)

	replayReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	validHeaders.Apply(replayReq.Header)
	replayResp := httptest.NewRecorder()
	handler.ServeHTTP(replayResp, replayReq)

	expiredHeaders, err := httpsig.SignRequest(service, http.MethodPost, "/callbacks/order-paid", "", validBody, time.Now().Add(-10*time.Minute), "nonce-1002")
	if err != nil {
		return err
	}
	expiredReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	expiredHeaders.Apply(expiredReq.Header)
	expiredResp := httptest.NewRecorder()
	handler.ServeHTTP(expiredResp, expiredReq)

	out.Println("valid status:", validResp.Code)
	out.Println("valid body:", validResp.Body.String())
	out.Println("replay status:", replayResp.Code)
	out.Println("expired status:", expiredResp.Code)
	return nil
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
	if err := os.MkdirAll(filepath.Join(root, kid), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, kid, "metadata.json"), raw, 0o600)
}
