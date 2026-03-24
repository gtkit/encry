package jwt

import (
	"errors"
	"fmt"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/jwt/claims"
)

// JwtHmac 签名结构.
type JwtHmac struct {
	secretKey []byte
	duration
	cache sync.Map
}

// NewJwtHmac 新建一个jwt实例.
func NewJwtHmac(secretKey []byte, options ...Options) (*JwtHmac, error) {
	if len(secretKey) == 0 {
		return nil, errors.New("secret key cannot be empty")
	}

	j := &JwtHmac{
		secretKey: append([]byte(nil), secretKey...),
		duration: duration{
			tokenDuration:   2 * time.Hour,
			refreshDuration: time.Hour * 24 * 7, // 默认7天,
		},
	}
	for _, opt := range options {
		opt(&j.duration)
	}

	return j, nil
}

// GenerateToken 生成token.
/**
 * 生成token.
 * @method GenerateToken.
 * @param  {[type]}       uid      int64  [description].
 * @param  {[type]}       duration time.Duration [签名过期时间,默认1小时].
 */
func (j *JwtHmac) GenerateToken(uid int64, options ...claims.Options) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	tokenID, err := generateTokenID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	tokenClaims := &claims.Claims{
		UserID:  uid,
		TokenID: tokenID,
		RegisteredClaims: gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(now.Add(j.tokenDuration)), // 签名过期时间，默认1小时
			NotBefore: gojwt.NewNumericDate(now),                      // 生效时间
			IssuedAt:  gojwt.NewNumericDate(now),                      // 生成签名的时间 （后续刷新 Token 不会更新）
			ID:        tokenID,                                        // 防止重放攻击
		},
	}

	for _, opt := range options {
		opt(tokenClaims)
	}

	token, err := createHmacToken(*tokenClaims, j.secretKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

// RefreshToken 更新token.
/**
 * 更新token.
 * @method RefreshToken.
 * @param  {[type]}      tokenID string [description].
 * @param  {[type]}      duration    time.Duration [description].
 */
func (j *JwtHmac) RefreshToken(tokenString string, opt ...gojwt.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	tokenClaims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return "", err
	}

	if err := refreshTokenClaims(tokenClaims, j.tokenDuration, j.refreshDuration); err != nil {
		return "", err
	}

	tokenClaims.RegisteredClaims.ID = tokenClaims.TokenID
	return createHmacToken(*tokenClaims, j.secretKey)
}

// ParseToken 解析Toknen.
/**
 * 解析token.
 * @method ParseToken.
 * @param  {[type]}    tokenString string [description].
 */
func (j *JwtHmac) ParseToken(tokenString string, opt ...gojwt.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	token, err := gojwt.ParseWithClaims(tokenString, &claims.Claims{}, func(token *gojwt.Token) (any, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	}, opt...)

	if err != nil {
		return nil, normalizeParseError(err)
	}

	if c, ok := token.Claims.(*claims.Claims); ok && token.Valid {
		return c, nil
	}
	return nil, ErrTokenInvalid
}

func (j *JwtHmac) CachedParseToken(tokenString string, opt ...gojwt.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}

	if c, ok := loadCachedClaims(&j.cache, tokenString); ok {
		return c, nil
	}

	tokenClaims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return nil, err
	}

	storeCachedClaims(&j.cache, tokenString, tokenClaims)
	return tokenClaims, nil
}

// ParallelVerify 并发解析token.
func (j *JwtHmac) ParallelVerify(tokens []string, opt ...gojwt.ParserOption) ([]*claims.Claims, []error) {
	var wg sync.WaitGroup
	results := make([]*claims.Claims, len(tokens))
	errs := make([]error, len(tokens))

	for i, token := range tokens {
		i, token := i, token
		wg.Go(func() {
			tokenClaims, err := j.ParseToken(token, opt...)
			results[i] = tokenClaims
			errs[i] = err
		})
	}

	wg.Wait()
	return results, errs
}

func createHmacToken(claims claims.Claims, signKey any) (string, error) {
	return gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims).SignedString(signKey)
}
