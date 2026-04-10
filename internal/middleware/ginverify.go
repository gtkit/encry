package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GinVerifyMiddleware 返回一个基于 X-Signature 头的 Gin 验签中间件.
func GinVerifyMiddleware(verifier SignatureVerifier) gin.HandlerFunc {
	return GinVerifyMiddlewareWithOptions(verifier, VerifyMiddlewareOptions{})
}

// GinVerifyMiddlewareWithOptions 返回一个基于 X-Signature 头的 Gin 验签中间件.
func GinVerifyMiddlewareWithOptions(verifier SignatureVerifier, opts VerifyMiddlewareOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		signature := c.GetHeader("X-Signature")
		if signature == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-Signature header"})
			return
		}

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

		ok, err := verifier.Verify(body, signature)
		if err != nil || !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "signature verification failed"})
			return
		}

		c.Next()
	}
}
