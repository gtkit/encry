package jwtauth

import (
	"crypto"
	stdrsa "crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/internal/keyring"
	jwtclaims "github.com/gtkit/encry/jwt/claims"
	encryrsa "github.com/gtkit/encry/rsa"
)

// RSAPSSOption 配置 JWT RSA-PSS 服务.
type RSAPSSOption func(*RSAPSSService)

// WithRSAPSSTokenDuration 设置默认 access token 有效期.
func WithRSAPSSTokenDuration(d time.Duration) RSAPSSOption {
	return func(s *RSAPSSService) {
		s.tokenDuration = d
	}
}

// WithRSAPSSNow 注入当前时间，方便测试.
func WithRSAPSSNow(now func() time.Time) RSAPSSOption {
	return func(s *RSAPSSService) {
		s.now = now
	}
}

// WithRSAPSSParserOptions 设置默认 parser options.
func WithRSAPSSParserOptions(options ...gojwt.ParserOption) RSAPSSOption {
	return func(s *RSAPSSService) {
		s.parserOptions = append(s.parserOptions, options...)
	}
}

// WithSigningMethod 设置 JWT 签名算法，默认使用 PS512.
func WithSigningMethod(method *gojwt.SigningMethodRSAPSS) RSAPSSOption {
	return func(s *RSAPSSService) {
		s.method = method
	}
}

// RSAPSSService 基于 metadata-aware RSA key ring 提供 JWT 签发、验签和 JWKS 发布.
type RSAPSSService struct {
	ring          *keyring.Ring[keyring.Record[keyring.RSAKeyPair]]
	tokenDuration time.Duration
	now           func() time.Time
	parserOptions []gojwt.ParserOption
	method        *gojwt.SigningMethodRSAPSS
}

// NewRSAPSS 创建一个新的 JWT RSA-PSS 服务.
func NewRSAPSS(ring *keyring.Ring[keyring.Record[keyring.RSAKeyPair]], options ...RSAPSSOption) *RSAPSSService {
	service := &RSAPSSService{
		ring:          ring,
		tokenDuration: 2 * time.Hour,
		now:           time.Now,
		method:        gojwt.SigningMethodPS512,
	}
	for _, opt := range options {
		opt(service)
	}
	return service
}

// Issue 生成一个带 kid 头的 JWT.
func (s *RSAPSSService) Issue(uid int64, options ...jwtclaims.Options) (string, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return "", err
	}
	record, err := keyring.ActiveRecord(snapshot, s.now())
	if err != nil {
		return "", err
	}

	tokenID, err := generateTokenID()
	if err != nil {
		return "", err
	}
	now := s.now()
	tokenClaims := &jwtclaims.Claims{
		UserID:  uid,
		TokenID: tokenID,
		RegisteredClaims: gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(now.Add(s.tokenDuration)),
			NotBefore: gojwt.NewNumericDate(now),
			IssuedAt:  gojwt.NewNumericDate(now),
			ID:        tokenID,
		},
	}
	for _, opt := range options {
		opt(tokenClaims)
	}

	token := gojwt.NewWithClaims(s.method, tokenClaims)
	token.Header["kid"] = record.Metadata.KID
	return token.SignedString(record.Key.Private)
}

// Parse 验证并解析 JWT.
func (s *RSAPSSService) Parse(tokenString string, options ...gojwt.ParserOption) (*jwtclaims.Claims, error) {
	parserOptions := append([]gojwt.ParserOption(nil), s.parserOptions...)
	parserOptions = append(parserOptions, options...)

	token, err := gojwt.ParseWithClaims(tokenString, &jwtclaims.Claims{}, func(token *gojwt.Token) (any, error) {
		if token.Method.Alg() != s.method.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid header")
		}

		snapshot, err := s.ring.Current()
		if err != nil {
			return nil, err
		}
		record, err := keyring.VerifyRecord(snapshot, kid, s.now())
		if err != nil {
			return nil, err
		}
		return record.Key.Public, nil
	}, parserOptions...)
	if err != nil {
		return nil, err
	}

	tokenClaims, ok := token.Claims.(*jwtclaims.Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return tokenClaims, nil
}

// JWKS 返回当前可发布的公钥集合.
func (s *RSAPSSService) JWKS() (keyring.JWKSet, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return keyring.JWKSet{}, err
	}
	return keyring.RSAPublicJWKSet(snapshot), nil
}

// VerifyJWKSignature 是一个帮助方法，便于示例或外部逻辑直接用当前 key ring 做 JWT 验签.
func (s *RSAPSSService) VerifyJWKSignature(payload []byte, signature string, kid string) (bool, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return false, err
	}
	record, err := keyring.VerifyRecord(snapshot, kid, s.now())
	if err != nil {
		return false, err
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	err = encryrsa.VerifyPSSWithPublicKey(record.Key.Public, payload, raw, crypto.Hash(s.method.Hash), &stdrsa.PSSOptions{
		SaltLength: stdrsa.PSSSaltLengthAuto,
		Hash:       crypto.Hash(s.method.Hash),
	})
	return err == nil, nil
}
