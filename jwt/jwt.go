// @Author xiaozhaofu 2022/11/11 18:11:00
package jwt

import (
	"fmt"
	"log"
	"sync"
	"time"
	// "github.com/golang-jwt/jwt"
	"github.com/golang-jwt/jwt/v5"
)

// JWT 签名结构
type JWT struct {
	SigningKey []byte
}

// 载荷
type CustomClaims struct {
	Subject int64  `json:"sub"`
	Prv     string `json:"prv"`
	Role    string `json:"role"`
	jwt.RegisteredClaims
}

var (
	once sync.Once
	j    *JWT
)

// 新建一个jwt实例
func NewJWT() *JWT {
	once.Do(func() {
		j = &JWT{
			[]byte(GetSignKey()),
		}
	})
	return j
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

// ParseToken 解析Toknen
/**
 * 解析token
 * @method ParseToken
 * @param  {[type]}    tokenString string [description]
 */
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

// RefreshToken 更新token
/**
 * 更新token
 * @method RefreshToken
 * @param  {[type]}      tokenString string [description]
 * @param  {[type]}      duration    time.Duration [description]
 */
func (j *JWT) RefreshToken(tokenString string, duration time.Duration) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(duration))
		return j.CreateToken(*claims)
	}

	return "", TokenInvalid
}

// GenerateToken 生成token
/**
 * 生成token
 * @method GenerateToken
 * @param  {[type]}       uid      int64  [description]
 * @param  {[type]}       duration time.Duration [description]
 */
func (j *JWT) GenerateToken(uid int64, duration time.Duration) (string, error) {

	// now := time.Now().Unix()
	prv := "23bd5c8949f600adb39e701c400872db7a5976f7"
	role := "client"
	claims := CustomClaims{
		uid,
		prv,
		role,
		jwt.RegisteredClaims{
			// duration := time.Hour * 24 * 90
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "",
			Subject:   "",
			ID:        "",
			Audience:  []string{},
		},
	}

	token, err := j.CreateToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

// CreateToken 生成一个token
func (j *JWT) CreateToken(claims CustomClaims) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	res, err := token.SignedString(j.SigningKey)
	log.Println("err:", err)
	return res, err
}

func (c CustomClaims) JwtSubject() int64 {
	return c.Subject
}
func (c CustomClaims) JwtRole() string {
	return c.Role
}
