package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
	
	gojwt "github.com/golang-jwt/jwt/v5"
)

// JWT 签名结构.
type JWT struct {
	secretKey       []byte
	tokenDuration   time.Duration
	refreshDuration time.Duration
	blacklist       Blacklister
}

// NewJWT 新建一个jwt实例.
func NewJWT(secretKey string, tokenDuration, refreshDuration time.Duration, blacklist ...Blacklister) *JWT {
	if secretKey == "" {
		return nil
	}
	
	if tokenDuration == 0 {
		tokenDuration = time.Hour
	}
	if refreshDuration == 0 {
		refreshDuration = time.Hour * 24 * 7 // 默认7天
	}
	
	var bl Blacklister
	if len(blacklist) > 0 {
		bl = blacklist[0]
	}
	
	return &JWT{
		secretKey:       []byte(secretKey),
		tokenDuration:   tokenDuration,
		refreshDuration: refreshDuration,
		blacklist:       bl,
	}
}

// GenerateToken 生成token.
/**
 * 生成token.
 * @method GenerateToken.
 * @param  {[type]}       uid      int64  [description].
 * @param  {[type]}       duration time.Duration [签名过期时间,默认1小时].
 */
func (j *JWT) GenerateToken(uid uint64, options ...ClaimsOptions) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	
	tokenID, err := generateTokenID()
	if err != nil {
		return "", err
	}
	
	now := time.Now()
	claims := &Claims{
		uid,
		"",
		nil,
		tokenID,
		gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(now.Add(j.tokenDuration)), // 签名过期时间，默认1小时
			NotBefore: gojwt.NewNumericDate(now),                      // 生效时间
			IssuedAt:  gojwt.NewNumericDate(now),                      // 生成签名的时间 （后续刷新 Token 不会更新）
		},
	}
	
	for _, opt := range options {
		opt(claims)
	}
	
	token, err := createToken(*claims, j.secretKey)
	if err != nil {
		return "", err
	}
	
	return token, nil
}

func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// RefreshToken 更新token.
/**
 * 更新token.
 * @method RefreshToken.
 * @param  {[type]}      tokenID string [description].
 * @param  {[type]}      duration    time.Duration [description].
 */
func (j *JWT) RefreshToken(tokenString string, opt ...gojwt.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	token, err := gojwt.ParseWithClaims(tokenString, &Claims{}, func(token *gojwt.Token) (any, error) {
		return j.secretKey, nil
	}, opt...)
	
	if err != nil {
		return "", err
	}
	
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// 只允许在令牌即将过期时刷新
		if time.Until(claims.ExpiresAt.Time) < 5*time.Minute {
			claims.RegisteredClaims.ExpiresAt = gojwt.NewNumericDate(time.Now().Add(j.refreshDuration))
			return createToken(*claims, j.secretKey)
		}
	}
	
	return "", ErrTokenInvalid
}

func createToken(claims Claims, signKey []byte) (string, error) {
	return gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims).SignedString(signKey)
}

// ParseToken 解析Toknen.
/**
 * 解析token.
 * @method ParseToken.
 * @param  {[type]}    tokenString string [description].
 */
func (j *JWT) ParseToken(tokenString string, opt ...gojwt.ParserOption) (*Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	token, err := gojwt.ParseWithClaims(tokenString, &Claims{}, func(token *gojwt.Token) (any, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodHMAC); !ok {
			log.Println("jwt parse error: unexpected signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	}, opt...)
	
	if err != nil {
		switch {
		case errors.Is(err, gojwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, gojwt.ErrTokenMalformed):
			return nil, ErrTokenMalformed
		case errors.Is(err, gojwt.ErrTokenNotValidYet):
			return nil, ErrTokenInvalid
		default:
			log.Printf("未知的JWT解析错误: %v", err)
			return nil, err
		}
	}
	
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrTokenInvalid
}

// CachedParseToken 缓存解析token.
var tokenCache = sync.Map{}

func (j *JWT) CachedParseToken(tokenString string, opt ...gojwt.ParserOption) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	
	key := base64.URLEncoding.EncodeToString([]byte(tokenString))
	
	if claims, ok := tokenCache.Load(key); ok {
		return claims.(*Claims), nil
	}
	
	claims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return nil, err
	}
	
	_, _ = tokenCache.LoadOrStore(key, claims)
	return claims, err
}

// ParallelVerify 并发解析token.
func (j *JWT) ParallelVerify(tokens []string, opt ...gojwt.ParserOption) ([]*Claims, []error) {
	var wg sync.WaitGroup
	results := make([]*Claims, len(tokens))
	errs := make([]error, len(tokens))
	
	for i, token := range tokens {
		wg.Go(func() {
			claims, err := j.ParseToken(token, opt...)
			results[i] = claims
			errs[i] = err
		})
	}
	
	wg.Wait()
	return results, errs
}

// 生成安全的密钥
func GenerateSecureKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(key), nil
}
