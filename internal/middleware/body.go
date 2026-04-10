package middleware

import (
	"errors"
	"io"
)

const DefaultMaxBodyBytes int64 = 1 << 20

var errRequestBodyTooLarge = errors.New("request body too large")

// VerifyMiddlewareOptions 控制基于完整 body 的验签中间件行为.
type VerifyMiddlewareOptions struct {
	MaxBodyBytes int64
}

func readRequestBody(body io.Reader, maxBodyBytes int64) ([]byte, error) {
	limit := maxBodyBytes
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}

	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errRequestBodyTooLarge
	}
	return data, nil
}
