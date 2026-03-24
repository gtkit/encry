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

	"github.com/gin-gonic/gin"
	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/cryptoenv"
	"github.com/gtkit/encry/internal/httpsig"
	"github.com/gtkit/encry/internal/keyring"
	"github.com/gtkit/encry/internal/middleware"
	"github.com/gtkit/encry/internal/signer"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	cfg, cleanup, err := cryptoenv.LoadKeyConfig(
		"ENCRY_GIN_ED25519_KEY_DIR",
		"ENCRY_GIN_ED25519_ACTIVE_KID",
		"encry-gin-middleware-*",
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
	nonceStore := httpsig.NewMemoryNonceStore()

	router := gin.New()
	router.Use(middleware.GinVerifyRequestMiddleware(service, httpsig.VerifyOptions{
		MaxSkew: 5 * time.Minute,
		Nonces:  nonceStore,
	}))
	router.POST("/callbacks/order-paid", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "accepted"})
	})

	validBody := []byte(`{"order_id":"1001","status":"paid"}`)
	validHeaders, err := httpsig.SignRequest(service, http.MethodPost, "/callbacks/order-paid", "", validBody, time.Now(), "nonce-2001")
	if err != nil {
		log.Fatal(err)
	}

	validReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	validHeaders.Apply(validReq.Header)
	validResp := httptest.NewRecorder()
	router.ServeHTTP(validResp, validReq)

	replayReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	validHeaders.Apply(replayReq.Header)
	replayResp := httptest.NewRecorder()
	router.ServeHTTP(replayResp, replayReq)

	expiredHeaders, err := httpsig.SignRequest(service, http.MethodPost, "/callbacks/order-paid", "", validBody, time.Now().Add(-10*time.Minute), "nonce-2002")
	if err != nil {
		log.Fatal(err)
	}
	expiredReq := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", bytes.NewReader(validBody))
	expiredHeaders.Apply(expiredReq.Header)
	expiredResp := httptest.NewRecorder()
	router.ServeHTTP(expiredResp, expiredReq)

	fmt.Println("valid status:", validResp.Code)
	fmt.Println("valid body:", validResp.Body.String())
	fmt.Println("replay status:", replayResp.Code)
	fmt.Println("expired status:", expiredResp.Code)
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
