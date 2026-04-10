package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/gtkit/encry/internal/httpsig"
)

// HTTPVerifyRequestMiddleware 返回一个基于 canonical request 的 net/http 验签中间件.
func HTTPVerifyRequestMiddleware(verifier httpsig.Verifier, opts httpsig.VerifyOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := readRequestBody(r.Body, opts.MaxBodyBytes)
			if err != nil {
				if errors.Is(err, errRequestBodyTooLarge) {
					http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "read request body failed", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			if err := httpsig.VerifyRequest(
				verifier,
				r.Method,
				r.URL.Path,
				r.URL.RawQuery,
				body,
				httpsig.FromHTTP(r.Header),
				opts,
			); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
