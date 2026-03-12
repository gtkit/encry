package jwt_test

import (
	"testing"
	"time"

	"github.com/gtkit/encry/jwt"
	"github.com/gtkit/encry/jwt/claims"
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
