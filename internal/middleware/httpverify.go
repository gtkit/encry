package middleware

import (
	"bytes"
	"io"
	"net/http"
)

// SignatureVerifier 定义基于完整 body 的签名验证接口.
type SignatureVerifier interface {
	Verify(payload []byte, signed string) (bool, error)
}

// HTTPVerifyMiddleware 返回一个基于 X-Signature 头的 net/http 验签中间件.
func HTTPVerifyMiddleware(verifier SignatureVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signature := r.Header.Get("X-Signature")
			if signature == "" {
				http.Error(w, "missing X-Signature header", http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read request body failed", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			ok, err := verifier.Verify(body, signature)
			if err != nil || !ok {
				http.Error(w, "signature verification failed", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
