package jwtauth

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/internal/keyring"
	jwtclaims "github.com/gtkit/encry/jwt/claims"
	encryrsa "github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/require"
)

func TestRSAPSSIssueParseAndJWKS(t *testing.T) {
	privateKey, publicKey, err := encryrsa.GenerateKeyPair(2048)
	require.NoError(t, err)

	ring := keyring.New[keyring.Record[keyring.RSAKeyPair]]()
	now := time.Now()
	require.NoError(t, ring.Store("2026-03", map[string]keyring.Record[keyring.RSAKeyPair]{
		"2026-03": {
			Key: keyring.RSAKeyPair{
				Private: privateKey,
				Public:  publicKey,
			},
			Metadata: keyring.Metadata{
				KID:       "2026-03",
				Algorithm: "PS512",
				Use:       "sig",
				Status:    keyring.StatusActive,
				NotBefore: now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			},
		},
	}))

	service := NewRSAPSS(ring,
		WithRSAPSSTokenDuration(time.Minute),
		WithRSAPSSNow(func() time.Time { return now }),
		WithRSAPSSParserOptions(gojwt.WithIssuer("acme-rsa")),
	)

	token, err := service.Issue(9, jwtclaims.WithIssuer("acme-rsa"))
	require.NoError(t, err)

	tokenClaims, err := service.Parse(token)
	require.NoError(t, err)
	require.Equal(t, int64(9), tokenClaims.UserID)

	jwks, err := service.JWKS()
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "2026-03", jwks.Keys[0].KID)
	require.Equal(t, "RSA", jwks.Keys[0].KTY)
}
