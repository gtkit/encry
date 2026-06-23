package main

import (
	"bytes"
	"context"
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
	"github.com/redis/go-redis/v9"
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

	redisAddr := os.Getenv("ENCRY_REDIS_ADDR")
	if redisAddr == "" {
		out.Println("set ENCRY_REDIS_ADDR to run Redis-backed nonce store demo")
		return nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return err
	}

	cfg, cleanup, err := cryptoenv.LoadKeyConfig(
		"ENCRY_HTTP_REDIS_ED25519_KEY_DIR",
		"ENCRY_HTTP_REDIS_ED25519_ACTIVE_KID",
		"encry-http-redis-*",
		filepath.Join("keys", "ed25519"),
		"2026-03",
	)
	if err != nil {
		return err
	}
	defer cleanup()

	if err = ensureEdKeys(cfg.KeyDir, "2026-03", keyring.StatusActive); err != nil {
		return err
	}

	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	records, err := keyring.LoadEd25519KeyPairRecords(cfg.KeyDir)
	if err != nil {
		return err
	}
	if err = ring.Store(cfg.ActiveKID, records); err != nil {
		return err
	}
	service := signer.NewManagedEd25519(ring)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /callbacks/order-paid", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("accepted"))
	})

	handler := middleware.HTTPVerifyRequestMiddleware(service, httpsig.VerifyOptions{
		MaxSkew:      5 * time.Minute,
		Nonces:       httpsig.NewRedisNonceStore(client, "encry:httpsig:nonce", 2*time.Second),
		MaxBodyBytes: 1 << 20,
	})(mux)

	body := []byte(`{"order_id":"1001","status":"paid"}`)
	headers, err := httpsig.SignRequest(service, http.MethodPost, "/callbacks/order-paid", "", body, time.Now(), "nonce-redis-1")
	if err != nil {
		return err
	}

	req := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(body))
	headers.Apply(req.Header)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	replayReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(body))
	headers.Apply(replayReq.Header)
	replayResp := httptest.NewRecorder()
	handler.ServeHTTP(replayResp, replayReq)

	out.Println("valid status:", resp.Code)
	out.Println("replay status:", replayResp.Code)
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
