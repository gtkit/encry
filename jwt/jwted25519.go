package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/jwt/claims"
)

// JwtEd25519 签名结构.
type JwtEd25519 struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	duration
	cache sync.Map
}

// NewJwtEd25519 新建一个jwt实例.
func NewJwtEd25519(priPath, pubPath string, options ...Options) (*JwtEd25519, error) {
	privateKey, err := readEd25519PrivateKey(priPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := readEd25519PublicKey(pubPath)
	if err != nil {
		return nil, err
	}

	j := &JwtEd25519{
		privateKey: privateKey,
		publicKey:  publicKey,
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
func (j *JwtEd25519) GenerateToken(uid int64, options ...claims.Options) (string, error) {
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

	token, err := createEd25519Token(*tokenClaims, j.privateKey)
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
func (j *JwtEd25519) RefreshToken(tokenString string, opt ...gojwt.ParserOption) (string, error) {
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
	return createEd25519Token(*tokenClaims, j.privateKey)
}

// ParseToken 解析Toknen.
/**
 * 解析token.
 * @method ParseToken.
 * @param  {[type]}    tokenString string [description].
 */
func (j *JwtEd25519) ParseToken(tokenString string, opt ...gojwt.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	token, err := gojwt.ParseWithClaims(tokenString, &claims.Claims{}, func(token *gojwt.Token) (any, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	}, opt...)

	if err != nil {
		return nil, normalizeParseError(err)
	}

	if c, ok := token.Claims.(*claims.Claims); ok && token.Valid {
		return c, nil
	}
	return nil, ErrTokenInvalid
}

func (j *JwtEd25519) CachedParseToken(tokenString string, opt ...gojwt.ParserOption) (*claims.Claims, error) {
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
func (j *JwtEd25519) ParallelVerify(tokens []string, opt ...gojwt.ParserOption) ([]*claims.Claims, []error) {
	var wg sync.WaitGroup
	results := make([]*claims.Claims, len(tokens))
	errs := make([]error, len(tokens))

	for i, token := range tokens {
		wg.Go(func() {
			tokenClaims, err := j.ParseToken(token, opt...)
			results[i] = tokenClaims
			errs[i] = err
		})
	}

	wg.Wait()
	return results, errs
}

func createEd25519Token(claims claims.Claims, signKey any) (string, error) {
	return gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims).SignedString(signKey)
}

func readEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Ed25519 private key size")
		}
		return ed25519.PrivateKey(append([]byte(nil), block.Bytes...)), nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("invalid private key type")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	default:
		return nil, fmt.Errorf("invalid private key PEM type: %s", block.Type)
	}
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "ED25519 PUBLIC KEY":
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key size")
		}
		return ed25519.PublicKey(append([]byte(nil), block.Bytes...)), nil
	case "PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("invalid public key type")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	default:
		return nil, fmt.Errorf("invalid public key PEM type: %s", block.Type)
	}
}

func readPEMBlock(path string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PEM %s: %w", path, ErrInvalidKey)
	}
	return block, nil
}
