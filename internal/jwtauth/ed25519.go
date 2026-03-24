package jwtauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/internal/keyring"
	jwtclaims "github.com/gtkit/encry/jwt/claims"
)

// Ed25519Service 基于 metadata-aware Ed25519 key ring 提供 JWT 签发、验签和 JWKS 发布.
type Ed25519Service struct {
	ring          *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]]
	tokenDuration time.Duration
	now           func() time.Time
	parserOptions []gojwt.ParserOption
}

// Option 配置 JWT Ed25519 服务.
type Option func(*Ed25519Service)

// WithTokenDuration 设置默认 access token 有效期.
func WithTokenDuration(d time.Duration) Option {
	return func(s *Ed25519Service) {
		s.tokenDuration = d
	}
}

// WithNow 注入当前时间，方便测试和可控签发.
func WithNow(now func() time.Time) Option {
	return func(s *Ed25519Service) {
		s.now = now
	}
}

// WithParserOptions 设置默认 parser options，比如 issuer / audience.
func WithParserOptions(options ...gojwt.ParserOption) Option {
	return func(s *Ed25519Service) {
		s.parserOptions = append(s.parserOptions, options...)
	}
}

// NewEd25519 创建一个新的 JWT Ed25519 服务.
func NewEd25519(ring *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]], options ...Option) *Ed25519Service {
	service := &Ed25519Service{
		ring:          ring,
		tokenDuration: 2 * time.Hour,
		now:           time.Now,
	}
	for _, opt := range options {
		opt(service)
	}
	return service
}

// Issue 生成一个带 kid 头的 JWT.
func (s *Ed25519Service) Issue(uid int64, options ...jwtclaims.Options) (string, error) {
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

	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, tokenClaims)
	token.Header["kid"] = record.Metadata.KID
	return token.SignedString(record.Key.Private)
}

// Parse 验证并解析 JWT.
func (s *Ed25519Service) Parse(tokenString string, options ...gojwt.ParserOption) (*jwtclaims.Claims, error) {
	parserOptions := append([]gojwt.ParserOption(nil), s.parserOptions...)
	parserOptions = append(parserOptions, options...)

	token, err := gojwt.ParseWithClaims(tokenString, &jwtclaims.Claims{}, func(token *gojwt.Token) (any, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodEd25519); !ok {
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
func (s *Ed25519Service) JWKS() (keyring.JWKSet, error) {
	snapshot, err := s.ring.Current()
	if err != nil {
		return keyring.JWKSet{}, err
	}
	return keyring.Ed25519PublicJWKSet(snapshot), nil
}

func generateTokenID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
