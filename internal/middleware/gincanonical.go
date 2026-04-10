package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gtkit/encry/internal/httpsig"
)

// GinVerifyRequestMiddleware 返回一个基于 canonical request 的 Gin 验签中间件.
func GinVerifyRequestMiddleware(verifier httpsig.Verifier, opts httpsig.VerifyOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := readRequestBody(c.Request.Body, opts.MaxBodyBytes)
		if err != nil {
			if errors.Is(err, errRequestBodyTooLarge) {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "read request body failed"})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		if err := httpsig.VerifyRequest(
			verifier,
			c.Request.Method,
			c.Request.URL.Path,
			c.Request.URL.RawQuery,
			body,
			httpsig.FromHTTP(c.Request.Header),
			opts,
		); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.Next()
	}
}
