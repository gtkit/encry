// @Author xiaozhaofu 2022/11/11 18:11:00
package jwt

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT 签名结构.
type JWT struct {
	SigningKey []byte
}

// CustomClaims 载荷.
type CustomClaims struct {
	Subject int64  `json:"sub"`
	Prv     string `json:"prv"`
	Role    string `json:"role"`
	// RegisteredClaims 结构体实现了 Claims 接口继承了  Valid() 方法
	// JWT 规定了7个官方字段，提供使用:
	// - iss (issuer)：发布者
	// - sub (subject)：主题
	// - iat (Issued At)：生成签名的时间
	// - exp (expiration time)：签名过期时间
	// - aud (audience)：观众，相当于接受者
	// - nbf (Not Before)：生效时间
	// - jti (JWT ID)：编号
	jwt.RegisteredClaims
}

var (
	once sync.Once
	j    *JWT
)

// NewJWT 新建一个jwt实例.
func NewJWT(key string) *JWT {
	once.Do(func() {
		j = &JWT{
			[]byte(key),
		}
	})
	return j
}

// ParseToken 解析Toknen.
/**
 * 解析token.
 * @method ParseToken.
 * @param  {[type]}    tokenString string [description].
 */
func (j *JWT) ParseToken(tokenString string, opt ...jwt.ParserOption) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Println("jwt parse error: unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.SigningKey, nil
	}, opt...)

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrTokenInvalid
}

// RefreshToken 更新token.
/**
 * 更新token.
 * @method RefreshToken.
 * @param  {[type]}      tokenString string [description].
 * @param  {[type]}      duration    time.Duration [description].
 */
func (j *JWT) RefreshToken(tokenString string, duration time.Duration, opt ...jwt.ParserOption) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		return j.SigningKey, nil
	}, opt...)

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(duration))
		return createToken(*claims, j.SigningKey)
	}

	return "", ErrTokenInvalid
}

// claims 可选参数.
type ClaimsOptions func(*CustomClaims)

func WithRole(role string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Role = role
	}
}
func WithPrv(prv string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Prv = prv
	}
}
func WithDuration(duration time.Duration) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(duration))
	}
}

// GenerateToken 生成token.
/**
 * 生成token.
 * @method GenerateToken.
 * @param  {[type]}       uid      int64  [description].
 * @param  {[type]}       duration time.Duration [签名过期时间,默认1小时].
 */
func (j *JWT) GenerateToken(uid int64, options ...ClaimsOptions) (string, error) {
	claims := &CustomClaims{
		uid,
		"",
		"",
		jwt.RegisteredClaims{
			Issuer:    "",                                            // 发布者
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), // 签名过期时间
			IssuedAt:  jwt.NewNumericDate(time.Now()),                // 生成签名的时间 （后续刷新 Token 不会更新）
			NotBefore: jwt.NewNumericDate(time.Now()),                // 生效时间
		},
	}
	log.Printf("claims 1: %+v", claims)

	for _, opt := range options {
		opt(claims)
	}
	log.Printf("claims 2: %+v", claims)

	token, err := createToken(*claims, j.SigningKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

func createToken(claims CustomClaims, signKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	res, err := token.SignedString(signKey)
	log.Println("err:", err)
	return res, err
}

func (c CustomClaims) JwtSubject() int64 {
	return c.Subject
}
func (c CustomClaims) JwtRole() string {
	return c.Role
}
