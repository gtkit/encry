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
	Subject int64  `json:"sub"`  // 用户ID
	Prv     string `json:"prv"`  // 不同模型的 JWT 进行隔离, 如: user, admin
	Role    string `json:"role"` // 角色, 如: admin, client
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

// WithRole 设置角色.
func WithRole(role string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Role = role
	}
}

// WithPrv 设置权限.
func WithPrv(prv string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Prv = prv
	}
}

// WithDuration 设置token过期时间.
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

	for _, opt := range options {
		opt(claims)
	}

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

func (c CustomClaims) UserId() int64 {
	return c.Subject
}

// VerifyRole 验证角色.
func (c CustomClaims) VerifyRole(role string) bool {
	return c.Role == role
}

// VerifyPrv 验证权限.
func (c CustomClaims) VerifyPrv(prv string) bool {
	return c.Prv == prv
}

// TTL 返回token剩余有效时间.
func (c CustomClaims) TTL() time.Duration {
	return c.ExpiresAt.Sub(time.Now())
}
