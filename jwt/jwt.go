// @Author xiaozhaofu 2022/11/11 18:11:00
package jwt

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWT 签名结构
type JWT struct {
	SigningKey []byte
}

var (
	TokenExpired     = errors.New("Token is expired")
	TokenNotValidYet = errors.New("Token not active yet")
	TokenMalformed   = errors.New("That's not even a token")
	TokenInvalid     = errors.New("Couldn't handle this token:")
	signKey          string // laravel 配置中的 JWT_SECRET
)

// 载荷
type CustomClaims struct {
	Subject int64  `json:"sub"`
	Prv     string `json:"prv"`
	Role    string `json:"role"`
	jwt.StandardClaims
}

// 新建一个jwt实例
func NewJWT() *JWT {
	return &JWT{
		[]byte(GetSignKey()),
	}
}

// 获取signKey
func GetSignKey() string {
	return signKey
}

// 这是SignKey
func SetSignKey(key string) string {
	signKey = key
	return signKey
}

// CreateToken 生成一个token
func (j *JWT) CreateToken(claims CustomClaims) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	res, err := token.SignedString(j.SigningKey)
	log.Println("err:", err)
	return res, err
}

// 解析Toknen
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Panicln("unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.SigningKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, TokenInvalid
}

// 更新token
func (j *JWT) RefreshToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		claims.StandardClaims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
		return j.CreateToken(*claims)
	}

	return "", TokenInvalid
}

func (j *JWT) GenerateToken(uid int64) (string, error) {

	now := time.Now().Unix()
	prv := "23bd5c8949f600adb39e701c400872db7a5976f7"
	role := "client"

	claims := CustomClaims{
		uid,
		prv,
		role,
		jwt.StandardClaims{
			IssuedAt:  now,
			NotBefore: now - 60,
			ExpiresAt: now + 1000,
			Issuer:    "man",
		},
	}

	token, err := j.CreateToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}
