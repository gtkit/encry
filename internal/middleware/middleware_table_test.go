package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gtkit/encry/internal/httpsig"
	"github.com/stretchr/testify/require"
)

// boolVerifier 按预设结果返回，覆盖验签成功/失败/错误.
type boolVerifier struct {
	ok  bool
	err error
}

func (v boolVerifier) Verify(_ []byte, _ string) (bool, error) {
	return v.ok, v.err
}

// canonicalVerifier 当签名等于 "kid.ok" 时通过，用于 canonical 中间件测试.
type canonicalVerifier struct{}

func (canonicalVerifier) Verify(_ []byte, signed string) (bool, error) {
	return signed == "kid.ok", nil
}

// errReader 模拟读取 body 失败.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("read boom")
}

// --- 基于 X-Signature 头的 net/http 中间件 ---

func TestSignatureMiddlewares(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		signature  string // 空表示不设置 X-Signature 头
		verifier   SignatureVerifier
		body       string
		wantStatus int
	}{
		{
			name:       "success",
			signature:  "kid.sig",
			verifier:   boolVerifier{ok: true},
			body:       "payload",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing signature header",
			signature:  "",
			verifier:   boolVerifier{ok: true},
			body:       "payload",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "verifier returns false",
			signature:  "kid.sig",
			verifier:   boolVerifier{ok: false},
			body:       "payload",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "verifier returns error",
			signature:  "kid.sig",
			verifier:   boolVerifier{err: errors.New("boom")},
			body:       "payload",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := HTTPVerifyMiddleware(tt.verifier)(okHandler())
			req := httptest.NewRequest(http.MethodPost, "/cb", strings.NewReader(tt.body))
			if tt.signature != "" {
				req.Header.Set("X-Signature", tt.signature)
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			require.Equal(t, tt.wantStatus, resp.Code)
		})
	}
}

func TestSignatureMiddlewaresReadError(t *testing.T) {
	t.Parallel()

	handler := HTTPVerifyMiddleware(boolVerifier{ok: true})(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/cb", errReader{})
	req.Header.Set("X-Signature", "kid.sig")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

// 验签成功时中间件需把 body 还原给下游处理器读取.
func TestSignatureMiddlewaresBodyRestored(t *testing.T) {
	t.Parallel()

	const body = "hello-body"

	var got string
	handler := HTTPVerifyMiddleware(boolVerifier{ok: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		got = string(data)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/cb", strings.NewReader(body))
	req.Header.Set("X-Signature", "kid.sig")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	require.Equal(t, body, got)
}

// --- 基于 canonical request 的 net/http 中间件 ---

func TestCanonicalRequestMiddlewares(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_710_000_000, 0)
	ts := strconv.FormatInt(at.Unix(), 10)
	now := func() time.Time { return at }

	tests := []struct {
		name       string
		signature  string
		timestamp  string
		nonce      string
		now        func() time.Time
		wantStatus int
	}{
		{name: "success", signature: "kid.ok", timestamp: ts, nonce: "nonce-1", now: now, wantStatus: http.StatusOK},
		{name: "signature mismatch", signature: "kid.bad", timestamp: ts, nonce: "nonce-1", now: now, wantStatus: http.StatusUnauthorized},
		{name: "missing signature", signature: "", timestamp: ts, nonce: "nonce-1", now: now, wantStatus: http.StatusUnauthorized},
		{name: "missing timestamp", signature: "kid.ok", timestamp: "", nonce: "nonce-1", now: now, wantStatus: http.StatusUnauthorized},
		{name: "missing nonce", signature: "kid.ok", timestamp: ts, nonce: "", now: now, wantStatus: http.StatusUnauthorized},
		{name: "timestamp skew", signature: "kid.ok", timestamp: ts, nonce: "nonce-1", now: func() time.Time { return at.Add(time.Hour) }, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := httpsig.VerifyOptions{Now: tt.now, MaxSkew: time.Minute}
			handler := HTTPVerifyRequestMiddleware(canonicalVerifier{}, opts)(okHandler())
			req := newSignedRequest(tt.signature, tt.timestamp, tt.nonce)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			require.Equal(t, tt.wantStatus, resp.Code)
		})
	}
}

// 校验 canonical 中间件的防重放：相同 nonce 第二次请求返回 401.
func TestCanonicalRequestMiddlewaresReplay(t *testing.T) {
	t.Parallel()

	// 用接近真实当前时间的时间戳：MemoryNonceStore 按真实墙钟清理过期 nonce，
	// 若用很久以前的固定时间戳，nonce 会被立即判为过期清掉，无法触发防重放。
	at := time.Now().Truncate(time.Second)
	ts := strconv.FormatInt(at.Unix(), 10)

	opts := httpsig.VerifyOptions{
		Now:     func() time.Time { return at },
		MaxSkew: time.Minute,
		Nonces:  httpsig.NewMemoryNonceStore(),
	}
	handler := HTTPVerifyRequestMiddleware(canonicalVerifier{}, opts)(okHandler())

	resp1 := httptest.NewRecorder()
	handler.ServeHTTP(resp1, newSignedRequest("kid.ok", ts, "nonce-replay"))
	require.Equal(t, http.StatusOK, resp1.Code)

	resp2 := httptest.NewRecorder()
	handler.ServeHTTP(resp2, newSignedRequest("kid.ok", ts, "nonce-replay"))
	require.Equal(t, http.StatusUnauthorized, resp2.Code)
}

func TestCanonicalRequestMiddlewaresReadError(t *testing.T) {
	t.Parallel()

	opts := httpsig.VerifyOptions{MaxSkew: time.Minute}
	handler := HTTPVerifyRequestMiddleware(canonicalVerifier{}, opts)(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/cb", errReader{})
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

// --- readRequestBody 直接单测 ---

func TestReadRequestBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		maxSize int64
		want    string
		wantErr error
	}{
		{name: "within limit", body: "1234", maxSize: 4, want: "1234"},
		{name: "exceeds limit", body: "12345", maxSize: 4, wantErr: errRequestBodyTooLarge},
		{name: "non-positive max uses default", body: "abc", maxSize: 0, want: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readRequestBody(strings.NewReader(tt.body), tt.maxSize)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, string(got))
		})
	}
}

func TestReadRequestBodyReadError(t *testing.T) {
	t.Parallel()

	_, err := readRequestBody(errReader{}, 16)
	require.Error(t, err)
	require.NotErrorIs(t, err, errRequestBodyTooLarge)
}

// --- helpers ---

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func newSignedRequest(signature, timestamp, nonce string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/cb", strings.NewReader(`{"ok":true}`))
	if signature != "" {
		req.Header.Set(httpsig.HeaderSignature, signature)
	}
	if timestamp != "" {
		req.Header.Set(httpsig.HeaderTimestamp, timestamp)
	}
	if nonce != "" {
		req.Header.Set(httpsig.HeaderNonce, nonce)
	}
	return req
}
