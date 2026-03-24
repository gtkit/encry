package jwt

import (
	"errors"
	"slices"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/encry/jwt/claims"
)

const refreshWindow = 5 * time.Minute

type cachedClaims struct {
	claims    *claims.Claims
	expiresAt time.Time
}

func normalizeParseError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gojwt.ErrTokenExpired):
		return ErrTokenExpired
	case errors.Is(err, gojwt.ErrTokenMalformed):
		return ErrTokenMalformed
	case errors.Is(err, gojwt.ErrTokenNotValidYet):
		return ErrTokenNotValidYet
	case errors.Is(err, gojwt.ErrTokenSignatureInvalid):
		return ErrTokenSignatureInvalid
	case errors.Is(err, gojwt.ErrTokenUnverifiable):
		return ErrTokenUnverifiable
	default:
		return err
	}
}

func loadCachedClaims(cache *sync.Map, token string) (*claims.Claims, bool) {
	value, ok := cache.Load(token)
	if !ok {
		return nil, false
	}

	entry, ok := value.(cachedClaims)
	if !ok || entry.claims == nil {
		cache.Delete(token)
		return nil, false
	}

	if !entry.expiresAt.IsZero() && !time.Now().Before(entry.expiresAt) {
		cache.Delete(token)
		return nil, false
	}

	return cloneClaims(entry.claims), true
}

func storeCachedClaims(cache *sync.Map, token string, tokenClaims *claims.Claims) {
	if tokenClaims == nil {
		return
	}

	entry := cachedClaims{
		claims: cloneClaims(tokenClaims),
	}
	if tokenClaims.ExpiresAt != nil {
		entry.expiresAt = tokenClaims.ExpiresAt.Time
	}
	cache.Store(token, entry)
}

func refreshTokenClaims(tokenClaims *claims.Claims, tokenDuration, refreshDuration time.Duration) error {
	if tokenClaims == nil || tokenClaims.ExpiresAt == nil || tokenClaims.IssuedAt == nil {
		return ErrTokenInvalid
	}

	now := time.Now()
	if now.Sub(tokenClaims.IssuedAt.Time) > refreshDuration {
		return ErrTokenExpired
	}
	if time.Until(tokenClaims.ExpiresAt.Time) >= refreshWindow {
		return ErrTokenInvalid
	}

	tokenClaims.ExpiresAt = gojwt.NewNumericDate(now.Add(tokenDuration))
	return nil
}

func cloneClaims(src *claims.Claims) *claims.Claims {
	if src == nil {
		return nil
	}

	dst := *src
	dst.RegisteredClaims = cloneRegisteredClaims(src.RegisteredClaims)
	dst.Roles = slices.Clone(src.Roles)
	return &dst
}

func cloneRegisteredClaims(src gojwt.RegisteredClaims) gojwt.RegisteredClaims {
	dst := src
	dst.ExpiresAt = cloneNumericDate(src.ExpiresAt)
	dst.NotBefore = cloneNumericDate(src.NotBefore)
	dst.IssuedAt = cloneNumericDate(src.IssuedAt)
	dst.Audience = append(gojwt.ClaimStrings(nil), src.Audience...)
	return dst
}

func cloneNumericDate(src *gojwt.NumericDate) *gojwt.NumericDate {
	if src == nil {
		return nil
	}
	return gojwt.NewNumericDate(src.Time)
}
