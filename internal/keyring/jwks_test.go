package keyring

import (
	"crypto/ed25519"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/gtkit/encry/ed"
	encryrsa "github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/require"
)

func TestEd25519PublicJWKSet(t *testing.T) {
	t.Parallel()

	pub, _, err := ed.GenerateKeyPair()
	require.NoError(t, err)
	created := time.Unix(1_710_000_000, 0).UTC()

	snapshot := &Snapshot[Record[Ed25519KeyPair]]{
		ActiveKID: "k1",
		Keys: map[string]Record[Ed25519KeyPair]{
			"k1": {
				Key: Ed25519KeyPair{Public: pub},
				Metadata: Metadata{
					KID:       "k1",
					Algorithm: "EdDSA",
					Use:       "sig",
					Status:    StatusActive,
					CreatedAt: created,
				},
			},
		},
	}

	set := Ed25519PublicJWKSet(snapshot)
	require.Len(t, set.Keys, 1)

	jwk := set.Keys[0]
	require.Equal(t, "k1", jwk.KID)
	require.Equal(t, "OKP", jwk.KTY)
	require.Equal(t, "Ed25519", jwk.Crv)
	require.Equal(t, "EdDSA", jwk.Alg)
	require.Equal(t, StatusActive, jwk.Status)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(pub), jwk.X)

	// X must decode back to the original 32-byte public key.
	decoded, derr := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, derr)
	require.Equal(t, pub, ed25519.PublicKey(decoded))
}

func TestEd25519PublicJWKSetEmpty(t *testing.T) {
	t.Parallel()

	snapshot := &Snapshot[Record[Ed25519KeyPair]]{Keys: map[string]Record[Ed25519KeyPair]{}}
	set := Ed25519PublicJWKSet(snapshot)
	require.Empty(t, set.Keys)
}

func TestRSAPublicJWKSet(t *testing.T) {
	t.Parallel()

	_, pub, err := encryrsa.GenerateKeyPair(2048)
	require.NoError(t, err)
	created := time.Unix(1_710_000_000, 0).UTC()

	snapshot := &Snapshot[Record[RSAKeyPair]]{
		ActiveKID: "rsa-1",
		Keys: map[string]Record[RSAKeyPair]{
			"rsa-1": {
				Key: RSAKeyPair{Public: pub},
				Metadata: Metadata{
					KID:       "rsa-1",
					Algorithm: "PS512",
					Use:       "sig",
					Status:    StatusActive,
					CreatedAt: created,
				},
			},
		},
	}

	set := RSAPublicJWKSet(snapshot)
	require.Len(t, set.Keys, 1)

	jwk := set.Keys[0]
	require.Equal(t, "rsa-1", jwk.KID)
	require.Equal(t, "RSA", jwk.KTY)
	require.Equal(t, "PS512", jwk.Alg)
	require.NotEmpty(t, jwk.N)
	require.NotEmpty(t, jwk.E)

	// N decodes back to the modulus.
	nBytes, derr := base64.RawURLEncoding.DecodeString(jwk.N)
	require.NoError(t, derr)
	require.Equal(t, 0, new(big.Int).SetBytes(nBytes).Cmp(pub.N))

	// E decodes back to the public exponent.
	eBytes, derr := base64.RawURLEncoding.DecodeString(jwk.E)
	require.NoError(t, derr)
	require.Equal(t, int64(pub.E), new(big.Int).SetBytes(eBytes).Int64())
}

func TestRSAPublicJWKSetEmpty(t *testing.T) {
	t.Parallel()

	snapshot := &Snapshot[Record[RSAKeyPair]]{Keys: map[string]Record[RSAKeyPair]{}}
	set := RSAPublicJWKSet(snapshot)
	require.Empty(t, set.Keys)
}

func TestJWKSetJSONRoundsAcrossKeys(t *testing.T) {
	t.Parallel()

	set := JWKSet{Keys: []JWK{
		{KID: "a", KTY: "OKP", Crv: "Ed25519", X: "xxx"},
		{KID: "b", KTY: "RSA", N: "nnn", E: "AQAB"},
	}}

	raw, err := set.JSON()
	require.NoError(t, err)
	require.Contains(t, string(raw), `"kid": "a"`)
	require.Contains(t, string(raw), `"kid": "b"`)
}
