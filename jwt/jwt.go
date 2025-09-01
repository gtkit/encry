package jwt

import (
	"fmt"
	"log"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// JWT 签名结构.
type JWT struct {
	SigningKey []byte
}

// CustomClaims 载荷.
type CustomClaims struct {
	UserID uint64 `json:"uid"`  // 用户ID
	Prv    string `json:"prv"`  // 扩展包自定义字段，模型名的哈希值，等于sha1(‘App\User’)，用于区别不同的模型
	Role   string `json:"role"` // 角色, 如: admin, client
	// RegisteredClaims 结构体实现了 Claims 接口继承了  Valid() 方法
	// JWT 规定了7个官方字段，提供使用:
	// - iss (issuer)：发布者
	// - sub (subject)：主题
	// - iat (Issued At)：生成签名的时间
	// - exp (expiration time)：签名过期时间
	// - aud (audience)：观众，相当于接受者
	// - nbf (Not Before)：生效时间
	// - jti (JWT ID)：编号
	gojwt.RegisteredClaims
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
func ParseToken(tokenString string, opt ...gojwt.ParserOption) (*CustomClaims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	token, err := gojwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *gojwt.Token) (any, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodHMAC); !ok {
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

// CachedParseToken 缓存解析token.
var tokenCache = sync.Map{}

func CachedParseToken(tokenString string, opt ...gojwt.ParserOption) (*CustomClaims, error) {
	if claims, ok := tokenCache.Load(tokenString); ok {
		return claims.(*CustomClaims), nil
	}

	claims, err := ParseToken(tokenString, opt...)
	if err == nil {
		tokenCache.Store(tokenString, claims)
	}
	return claims, err
}

// ParallelVerify 并发解析token.
func ParallelVerify(tokens []string, opt ...gojwt.ParserOption) ([]*CustomClaims, []error) {
	var wg sync.WaitGroup
	results := make([]*CustomClaims, len(tokens))
	errs := make([]error, len(tokens))

	for i, token := range tokens {
		wg.Go(func() {
			claims, err := ParseToken(token, opt...)
			results[i] = claims
			errs[i] = err
		})
	}

	wg.Wait()
	return results, errs
}

// RefreshToken 更新token.
/**
 * 更新token.
 * @method RefreshToken.
 * @param  {[type]}      tokenString string [description].
 * @param  {[type]}      duration    time.Duration [description].
 */
func RefreshToken(tokenString string, duration time.Duration, opt ...gojwt.ParserOption) (string, error) {
	token, err := gojwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *gojwt.Token) (any, error) {
		return j.SigningKey, nil
	}, opt...)

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		// 只允许在令牌即将过期时刷新
		if time.Until(claims.ExpiresAt.Time) < 5*time.Minute {
			claims.RegisteredClaims.ExpiresAt = gojwt.NewNumericDate(time.Now().Add(duration))
			return createToken(*claims, j.SigningKey)
		}
	}

	return "", ErrTokenInvalid
}

// GenerateToken 生成token.
/**
 * 生成token.
 * @method GenerateToken.
 * @param  {[type]}       uid      int64  [description].
 * @param  {[type]}       duration time.Duration [签名过期时间,默认1小时].
 */
func GenerateToken(uid uint64, options ...ClaimsOptions) (string, error) {
	claims := &CustomClaims{
		uid,
		"",
		"",
		gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)), // 签名过期时间，默认1小时
			NotBefore: gojwt.NewNumericDate(time.Now()),                // 生效时间
			IssuedAt:  gojwt.NewNumericDate(time.Now()),                // 生成签名的时间 （后续刷新 Token 不会更新）
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
	return gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims).SignedString(signKey)
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

// WithIssuer 设置发布者.
func WithIssuer(issuer string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Issuer = issuer
	}
}

// WithSubject 设置主题.
func WithSubject(subject string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Subject = subject
	}
}

// WithAudience 设置观众.
func WithAudience(audience ...string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.Audience = append(claims.Audience, audience...)
	}
}

// WithExpiresAt 设置过期时间.
func WithExpiresAt(expiresAt time.Duration) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.ExpiresAt = gojwt.NewNumericDate(time.Now().Add(expiresAt))
	}
}

// WithJwtID (JWT ID) the `jti` 设置编号.
func WithJwtID(jwtID string) ClaimsOptions {
	return func(claims *CustomClaims) {
		claims.ID = jwtID
	}
}

// 用户信息获取，角色验证，模型验证，token剩余有效时间获取.

// UserId 获取用户ID.
func (c CustomClaims) UserId() uint64 {
	return c.UserID
}

// VerifyRole 验证角色.
func (c CustomClaims) VerifyRole(role string) error {
	if c.Role == role {
		return nil
	}
	return ErrTokenRole
}

// VerifyPrv 验证模型.
func (c CustomClaims) VerifyPrv(prv string) error {
	if c.Prv == prv {
		return nil
	}
	return ErrTokenPrv
}

// TTL 返回token剩余有效时间.
func (c CustomClaims) TTL() time.Duration {
	return c.ExpiresAt.Sub(time.Now())
}

/**
 * 黑名单接口.
 * @interface Blacklister.
 * @method IsTokenBlacklisted.
 * @param  {[type]}    tokenString string [用户token].
 * @method AddTokenToBlacklist.
 * @param  {[type]}    tokenString string [用户token].
 */
type Blacklister interface {
	In(tokenString string) bool
	Add(tokenString string)
	Remove(tokenString string)
}

type blacklist map[string]struct{}

// NewBlacklist 新建黑名单.
func NewBlacklist() Blacklister {
	return blacklist(make(map[string]struct{}))
}

func (b blacklist) In(tokenString string) bool {
	_, ok := b[tokenString]
	return ok
}

func (b blacklist) Add(tokenString string) {
	b[tokenString] = struct{}{}
}

func (b blacklist) Remove(tokenString string) {
	delete(b, tokenString)
}

/**
 * 判断token是否在黑名单中.
 * @method InBlacklist.
 * @param  {[type]}    bl          Blacklister [黑名单接口].
 * @param  {[type]}    tokenString string [用户token].
 */
func InBlacklist(bl Blacklister, tokenString string) bool {
	return bl.In(tokenString)
}

/**
 * 添加token到黑名单.
 * @method AddTokenToBlacklist.
 * @param  {[type]}    bl          Blacklister [黑名单接口].
 * @param  {[type]}    tokenString string [用户token].
 */
func AddToBlacklist(bl Blacklister, tokenString string) {
	bl.Add(tokenString)
}

/**
 * 移除token.
 * @method RemoveTokenFromBlacklist.
 * @param  {[type]}    bl          Blacklister [黑名单接口].
 * @param  {[type]}    tokenString string [用户token].
 */
func RemoveFromBlacklist(bl Blacklister, tokenString string) {
	bl.Remove(tokenString)
}
