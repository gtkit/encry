package jwt_test

import (
	"testing"
	"time"

	"github.com/gtkit/encry/jwt"
)

func TestJwtGenerate(t *testing.T) {
	key := "t8yij6okp2ldadg7feqoibjladj92gjh"
	j := jwt.NewJWT(key)
	token, err := j.GenerateToken(10, jwt.WithExpiresAt(time.Hour*24), jwt.WithRole("admin"), jwt.WithPrv("prv1"))
	if err != nil {
		t.Error("generate token error:", err)
		return
	}
	t.Log("token:", token)

	claim, err := j.ParseToken(token)
	if err != nil {
		t.Error("parse token error:", err)
		return
	}
	t.Logf("claim: %+v", claim)
}
