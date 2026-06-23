package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gtkit/encry/internal/httpsig"
	"github.com/stretchr/testify/require"
)

type countingVerifier struct {
	calls int
}

func (v *countingVerifier) Verify(_ []byte, _ string) (bool, error) {
	v.calls++
	return true, nil
}

func TestHTTPVerifyMiddlewareWithOptionsRejectsBodyTooLarge(t *testing.T) {
	verifier := &countingVerifier{}
	handler := HTTPVerifyMiddlewareWithOptions(verifier, VerifyMiddlewareOptions{
		MaxBodyBytes: 4,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", strings.NewReader("12345"))
	req.Header.Set("X-Signature", "kid.signature")
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
	require.Zero(t, verifier.calls)
}

func TestHTTPVerifyRequestMiddlewareRejectsBodyTooLarge(t *testing.T) {
	verifier := &countingVerifier{}
	handler := HTTPVerifyRequestMiddleware(verifier, httpsig.VerifyOptions{
		MaxBodyBytes: 4,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/callbacks/order-paid", strings.NewReader("12345"))
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
	require.Zero(t, verifier.calls)
}
