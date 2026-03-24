package jwt_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gtkit/encry/jwt"
	"github.com/gtkit/encry/jwt/claims"
	"github.com/stretchr/testify/require"
)

func TestJwtGenerate(t *testing.T) {
	key := "t8yij6okp2ldadg7feqoibjladj92gjh"
	j, _ := jwt.NewJwtHmac([]byte(key))
	token, err := j.GenerateToken(10,
		claims.WithExpiresAt(time.Hour*24),
		claims.WithRoles("admin", "Finance"),
		claims.WithPrv("prv1"),
	)
	if err != nil {
		t.Error("generate token error:", err)
		return
	}
	t.Log("token:", token)

	// 解析token
	claims, err := j.ParseToken(token)
	if err != nil {
		t.Error("parse token error:", err)
		return
	}
	t.Logf("claim: %+v", claims)

	// 加入黑名单
	//j.AddToBlacklist(claims.TokenID)
	//// 判断是否在黑名单
	//if j.InBlacklist(claims.TokenID) {
	//	t.Log("token in blacklist")
	//}
	//// 移除黑名单
	//j.RemoveFromBlacklist(claims.TokenID)
	//// 判断是否移除成功
	//if !j.InBlacklist(claims.TokenID) {
	//	t.Log("token removed from blacklist")
	//}
}

func TestJwtOptionsApplyToTokenDuration(t *testing.T) {
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")
	j, err := jwt.NewJwtHmac(key, jwt.WithTokenDuration(time.Minute))
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Less(t, tokenClaims.TTL(), time.Minute+5*time.Second)
}

func TestCachedParseTokenIsScopedToInstanceSecret(t *testing.T) {
	first, err := jwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
	require.NoError(t, err)
	second, err := jwt.NewJwtHmac([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	require.NoError(t, err)

	token, err := first.GenerateToken(42)
	require.NoError(t, err)

	_, err = first.CachedParseToken(token)
	require.NoError(t, err)

	_, err = second.CachedParseToken(token)
	require.Error(t, err)
}

func TestRefreshTokenKeepsAccessTokenTTL(t *testing.T) {
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")
	j, err := jwt.NewJwtHmac(
		key,
		jwt.WithTokenDuration(time.Second),
		jwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)
	require.Less(t, tokenClaims.TTL(), 5*time.Second)
}

func TestJwtEd25519GenerateAndParse(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")

	require.NoError(t, jwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := jwt.NewJwtEd25519(priPath, pubPath)
	require.NoError(t, err)

	token, err := j.GenerateToken(99)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, int64(99), tokenClaims.UserID)
}
