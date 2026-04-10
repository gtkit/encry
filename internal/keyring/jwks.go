package keyring

import (
	"encoding/base64"
	"math/big"
	"time"

	json "github.com/gtkit/json"
)

// JWKSet 是一个精简的 JWKS-like 公钥发布结构.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWK 表示一个可发布的公钥条目.
type JWK struct {
	KID       string    `json:"kid"`
	KTY       string    `json:"kty"`
	Use       string    `json:"use,omitzero"`
	Alg       string    `json:"alg,omitzero"`
	Status    KeyStatus `json:"status,omitzero"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`

	Crv string `json:"crv,omitzero"`
	X   string `json:"x,omitzero"`
	N   string `json:"n,omitzero"`
	E   string `json:"e,omitzero"`
}

// JSON 把 JWKSet 编码成格式化 JSON.
func (s JWKSet) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// Ed25519PublicJWKSet 从 metadata-aware Ed25519 snapshot 构造可发布公钥集.
func Ed25519PublicJWKSet(snapshot *Snapshot[Record[Ed25519KeyPair]]) JWKSet {
	keys := make([]JWK, 0, len(snapshot.Keys))
	for kid, record := range snapshot.Keys {
		keys = append(keys, JWK{
			KID:       kid,
			KTY:       "OKP",
			Use:       record.Metadata.Use,
			Alg:       record.Metadata.Algorithm,
			Status:    record.Metadata.Status,
			CreatedAt: record.Metadata.CreatedAt,
			ExpiresAt: record.Metadata.ExpiresAt,
			RevokedAt: record.Metadata.RevokedAt,
			Crv:       "Ed25519",
			X:         base64.RawURLEncoding.EncodeToString(record.Key.Public),
		})
	}
	return JWKSet{Keys: keys}
}

// RSAPublicJWKSet 从 metadata-aware RSA snapshot 构造可发布公钥集.
func RSAPublicJWKSet(snapshot *Snapshot[Record[RSAKeyPair]]) JWKSet {
	keys := make([]JWK, 0, len(snapshot.Keys))
	for kid, record := range snapshot.Keys {
		e := big.NewInt(int64(record.Key.Public.E)).Bytes()
		keys = append(keys, JWK{
			KID:       kid,
			KTY:       "RSA",
			Use:       record.Metadata.Use,
			Alg:       record.Metadata.Algorithm,
			Status:    record.Metadata.Status,
			CreatedAt: record.Metadata.CreatedAt,
			ExpiresAt: record.Metadata.ExpiresAt,
			RevokedAt: record.Metadata.RevokedAt,
			N:         base64.RawURLEncoding.EncodeToString(record.Key.Public.N.Bytes()),
			E:         base64.RawURLEncoding.EncodeToString(e),
		})
	}
	return JWKSet{Keys: keys}
}
