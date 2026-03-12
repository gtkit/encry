package jwt

import "time"

type duration struct {
	tokenDuration   time.Duration
	refreshDuration time.Duration
}

type Options func(duration)

// WithTokenDuration 设置token过期时间.
func WithTokenDuration(t time.Duration) Options {
	return func(d duration) {
		d.tokenDuration = t
	}
}

// WithRefreshDuration 设置refresh token过期时间.
func WithRefreshDuration(t time.Duration) Options {
	return func(d duration) {
		d.refreshDuration = t
	}
}
