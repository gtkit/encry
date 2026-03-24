package jwtauth

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/keyring"
	jwtclaims "github.com/gtkit/encry/jwt/claims"
	"github.com/stretchr/testify/require"
)

func TestEd25519IssueParseAndJWKS(t *testing.T) {
	publicKey, privateKey, err := ed.GenerateKeyPair()
	require.NoError(t, err)

	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	now := time.Now()
	require.NoError(t, ring.Store("2026-03", map[string]keyring.Record[keyring.Ed25519KeyPair]{
		"2026-03": {
			Key: keyring.Ed25519KeyPair{
				Private: privateKey,
				Public:  publicKey,
			},
			Metadata: keyring.Metadata{
				KID:       "2026-03",
				Algorithm: "EdDSA",
				Use:       "sig",
				Status:    keyring.StatusActive,
				NotBefore: now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			},
		},
	}))

	service := NewEd25519(ring, WithNow(func() time.Time { return now }), WithParserOptions(gojwt.WithIssuer("acme")))

	token, err := service.Issue(7, jwtclaims.WithIssuer("acme"))
	require.NoError(t, err)

	tokenClaims, err := service.Parse(token)
	require.NoError(t, err)
	require.Equal(t, int64(7), tokenClaims.UserID)

	jwks, err := service.JWKS()
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "2026-03", jwks.Keys[0].KID)
}
