package jwt

import (
	"slices"
	"time"
	
	gojwt "github.com/golang-jwt/jwt/v5"
)

// Claims 载荷.
type Claims struct {
	UserID  uint64   `json:"uid"`   // 用户ID
	Prv     string   `json:"prv"`   // 扩展包自定义字段，模型名的哈希值，等于sha1(‘App\User’)，用于区别不同的模型
	Roles   []string `json:"roles"` // 角色, 如: admin, client
	TokenID string   `json:"token_id"`
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

// claims 可选参数.
type ClaimsOptions func(*Claims)

// WithRole 设置角色.
func WithRole(role string) ClaimsOptions {
	return func(claims *Claims) {
		claims.Roles = append(claims.Roles, role)
	}
}

func WithRoles(roles ...string) ClaimsOptions {
	return func(claims *Claims) {
		claims.Roles = append(claims.Roles, roles...)
	}
}

// WithPrv 设置权限.
func WithPrv(prv string) ClaimsOptions {
	return func(claims *Claims) {
		claims.Prv = prv
	}
}

// WithIssuer 设置发布者.
func WithIssuer(issuer string) ClaimsOptions {
	return func(claims *Claims) {
		claims.Issuer = issuer
	}
}

// WithSubject 设置主题.
func WithSubject(subject string) ClaimsOptions {
	return func(claims *Claims) {
		claims.Subject = subject
	}
}

// WithAudience 设置观众.
func WithAudience(audience ...string) ClaimsOptions {
	return func(claims *Claims) {
		claims.Audience = append(claims.Audience, audience...)
	}
}

// WithExpiresAt 设置过期时间.
func WithExpiresAt(expiresAt time.Duration) ClaimsOptions {
	return func(claims *Claims) {
		claims.ExpiresAt = gojwt.NewNumericDate(time.Now().Add(expiresAt))
	}
}

// WithJwtID (JWT ID) the `jti` 设置编号.
func WithJwtID(jwtID string) ClaimsOptions {
	return func(claims *Claims) {
		claims.ID = jwtID
	}
}

// 用户信息获取，角色验证，模型验证，token剩余有效时间获取.

// UserId 获取用户ID.
func (c Claims) UserId() uint64 {
	return c.UserID
}

// VerifyRole 验证角色.
func (c Claims) VerifyRole(roles ...string) error {
	if slices.Compare(c.Roles, roles) == 0 {
		return nil
	}
	return ErrTokenRole
}

// VerifyPrv 验证模型.
func (c Claims) VerifyPrv(prv string) error {
	if c.Prv == prv {
		return nil
	}
	return ErrTokenPrv
}

// TTL 返回token剩余有效时间.
func (c Claims) TTL() time.Duration {
	return c.ExpiresAt.Sub(time.Now())
}
