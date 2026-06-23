package httpsig

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stubSigner 在测试中提供可控的签名结果.
type stubSigner struct {
	signature string
	err       error
}

func (s stubSigner) Sign(_ []byte) (string, error) {
	return s.signature, s.err
}

// errVerifier 总是返回错误，用于覆盖验签错误路径.
type errVerifier struct {
	err error
}

func (v errVerifier) Verify(_ []byte, _ string) (bool, error) {
	return false, v.err
}

func TestCanonicalPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string
		path      string
		query     string
		body      []byte
		timestamp string
		nonce     string
		want      string
	}{
		{
			name:      "lowercase method is upcased",
			method:    "post",
			path:      "/callbacks/order-paid",
			query:     "a=1&b=2",
			body:      []byte(`{"ok":true}`),
			timestamp: "1710000000",
			nonce:     "nonce-1",
			want:      "POST\n/callbacks/order-paid\na=1&b=2\n1710000000\nnonce-1\n" + BodyDigestHex([]byte(`{"ok":true}`)),
		},
		{
			name:      "empty path defaults to slash",
			method:    "GET",
			path:      "",
			query:     "",
			body:      nil,
			timestamp: "1710000000",
			nonce:     "nonce-2",
			want:      "GET\n/\n\n1710000000\nnonce-2\n" + BodyDigestHex(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CanonicalPayload(tt.method, tt.path, tt.query, tt.body, tt.timestamp, tt.nonce)
			require.Equal(t, tt.want, string(got))
		})
	}
}

func TestBodyDigestHex(t *testing.T) {
	t.Parallel()

	// 空 body 的 SHA256 摘要是固定值.
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	require.Equal(t, emptySHA256, BodyDigestHex(nil))
	require.Equal(t, emptySHA256, BodyDigestHex([]byte{}))
	require.NotEqual(t, emptySHA256, BodyDigestHex([]byte("x")))
}

func TestHeadersApplyAndFromHTTP(t *testing.T) {
	t.Parallel()

	headers := Headers{
		Signature: "kid.sig",
		Timestamp: "1710000000",
		Nonce:     "nonce-1",
	}

	dst := http.Header{}
	headers.Apply(dst)
	require.Equal(t, "kid.sig", dst.Get(HeaderSignature))
	require.Equal(t, "1710000000", dst.Get(HeaderTimestamp))
	require.Equal(t, "nonce-1", dst.Get(HeaderNonce))

	got := FromHTTP(dst)
	require.Equal(t, headers, got)
}

func TestSignRequest(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_710_000_000, 0)

	tests := []struct {
		name       string
		signer     Signer
		wantErr    bool
		wantHeader Headers
	}{
		{
			name:   "success",
			signer: stubSigner{signature: "kid.ok"},
			wantHeader: Headers{
				Signature: "kid.ok",
				Timestamp: strconv.FormatInt(at.Unix(), 10),
				Nonce:     "nonce-1",
			},
		},
		{
			name:    "signer error",
			signer:  stubSigner{err: errors.New("sign boom")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := SignRequest(tt.signer, "POST", "/path", "q=1", []byte("body"), at, "nonce-1")
			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, Headers{}, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantHeader, got)
		})
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_710_000_000, 0)
	signer := stubSigner{signature: "kid.ok"}
	verifier := &stubVerifier{}

	headers, err := SignRequest(signer, "POST", "/path", "q=1", []byte("body"), at, "nonce-1")
	require.NoError(t, err)

	err = VerifyRequest(
		context.Background(),
		verifier,
		"POST", "/path", "q=1", []byte("body"),
		headers,
		VerifyOptions{Now: func() time.Time { return at }, MaxSkew: time.Minute},
	)
	require.NoError(t, err)
}

func TestVerifyRequestValidation(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_710_000_000, 0)
	ts := strconv.FormatInt(at.Unix(), 10)
	now := func() time.Time { return at }

	base := Headers{Signature: "kid.ok", Timestamp: ts, Nonce: "nonce-1"}

	tests := []struct {
		name    string
		headers Headers
		now     func() time.Time
		maxSkew time.Duration
		wantErr error
	}{
		{
			name:    "missing signature",
			headers: Headers{Timestamp: ts, Nonce: "nonce-1"},
			wantErr: ErrMissingSignature,
		},
		{
			name:    "missing timestamp",
			headers: Headers{Signature: "kid.ok", Nonce: "nonce-1"},
			wantErr: ErrMissingTimestamp,
		},
		{
			name:    "missing nonce",
			headers: Headers{Signature: "kid.ok", Timestamp: ts},
			wantErr: ErrMissingNonce,
		},
		{
			name:    "invalid timestamp",
			headers: Headers{Signature: "kid.ok", Timestamp: "not-a-number", Nonce: "nonce-1"},
			wantErr: ErrInvalidTimestamp,
		},
		{
			name:    "timestamp too old",
			headers: base,
			now:     func() time.Time { return at.Add(10 * time.Minute) },
			maxSkew: time.Minute,
			wantErr: ErrTimestampSkew,
		},
		{
			name:    "timestamp too new",
			headers: base,
			now:     func() time.Time { return at.Add(-10 * time.Minute) },
			maxSkew: time.Minute,
			wantErr: ErrTimestampSkew,
		},
		{
			name:    "signature mismatch",
			headers: Headers{Signature: "kid.bad", Timestamp: ts, Nonce: "nonce-1"},
			wantErr: ErrSignatureInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nowFn := now
			if tt.now != nil {
				nowFn = tt.now
			}
			verifier := &stubVerifier{}
			vErr := VerifyRequest(
				context.Background(),
				verifier,
				"POST", "/path", "", []byte("body"),
				tt.headers,
				VerifyOptions{Now: nowFn, MaxSkew: tt.maxSkew},
			)
			require.ErrorIs(t, vErr, tt.wantErr)
		})
	}
}

func TestVerifyRequestVerifierError(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_710_000_000, 0)
	wantErr := errors.New("verify boom")
	headers := Headers{Signature: "kid.ok", Timestamp: strconv.FormatInt(at.Unix(), 10), Nonce: "nonce-1"}

	err := VerifyRequest(
		context.Background(),
		errVerifier{err: wantErr},
		"POST", "/path", "", []byte("body"),
		headers,
		VerifyOptions{Now: func() time.Time { return at }, MaxSkew: time.Minute},
	)
	require.ErrorIs(t, err, wantErr)
}

// nonceStoreError 让 nonce store 返回错误，覆盖 VerifyRequest 中 Nonces 的错误分支.
type nonceStoreError struct {
	err error
}

func (n nonceStoreError) Use(_ context.Context, _ string, _ time.Time) (bool, error) {
	return false, n.err
}

func TestVerifyRequestNonceStoreError(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_710_000_000, 0)
	wantErr := errors.New("store boom")
	headers := Headers{Signature: "kid.ok", Timestamp: strconv.FormatInt(at.Unix(), 10), Nonce: "nonce-1"}

	err := VerifyRequest(
		context.Background(),
		&stubVerifier{},
		"POST", "/path", "", []byte("body"),
		headers,
		VerifyOptions{Now: func() time.Time { return at }, MaxSkew: time.Minute, Nonces: nonceStoreError{err: wantErr}},
	)
	require.ErrorIs(t, err, wantErr)
}

func TestVerifyRequestNilContextAndDefaultSkew(t *testing.T) {
	t.Parallel()

	// 不设置 Now 与 MaxSkew，走默认 5 分钟窗口与 time.Now，并传入 nil context.
	at := time.Now()
	headers := Headers{Signature: "kid.ok", Timestamp: strconv.FormatInt(at.Unix(), 10), Nonce: "nonce-1"}

	//nolint:staticcheck // SA1012: 故意测试 nil context 的兜底分支
	err := VerifyRequest(
		nil,
		&stubVerifier{},
		"POST", "/path", "", []byte("body"),
		headers,
		VerifyOptions{},
	)
	require.NoError(t, err)
}

func TestMemoryNonceStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryNonceStore()
	require.NotNil(t, store)

	expiresAt := time.Now().Add(time.Minute)

	ok, err := store.Use(context.Background(), "key-1", expiresAt)
	require.NoError(t, err)
	require.True(t, ok)

	// 同一 key 未过期再次使用视为重放.
	ok, err = store.Use(context.Background(), "key-1", expiresAt)
	require.NoError(t, err)
	require.False(t, ok)

	// 不同 key 不受影响.
	ok, err = store.Use(context.Background(), "key-2", expiresAt)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMemoryNonceStoreExpiredKeyIsReusable(t *testing.T) {
	t.Parallel()

	store := NewMemoryNonceStore()

	// 写入一个已经过期的 key，下一次 Use 应清理后允许占用.
	expired := time.Now().Add(-time.Minute)
	ok, err := store.Use(context.Background(), "key-1", expired)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = store.Use(context.Background(), "key-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMemoryNonceStoreNilContext(t *testing.T) {
	t.Parallel()

	store := NewMemoryNonceStore()
	//nolint:staticcheck // SA1012: 故意测试 nil context 的兜底分支
	ok, err := store.Use(nil, "key-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMemoryNonceStoreCanceledContext(t *testing.T) {
	t.Parallel()

	store := NewMemoryNonceStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := store.Use(ctx, "key-1", time.Now().Add(time.Minute))
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, ok)
}

func TestMemoryNonceStoreConcurrent(t *testing.T) {
	t.Parallel()

	store := NewMemoryNonceStore()
	const goroutines = 50
	expiresAt := time.Now().Add(time.Minute)

	done := make(chan struct{})
	for i := range goroutines {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			key := "key-" + strconv.Itoa(idx)
			ok, err := store.Use(context.Background(), key, expiresAt)
			require.NoError(t, err)
			require.True(t, ok)
		}(i)
	}
	for range goroutines {
		<-done
	}
}

// 确认 CanonicalPayload 的输出在 body 内容变化时也变化（防止裁剪 body 影响摘要）.
func TestCanonicalPayloadBodySensitive(t *testing.T) {
	t.Parallel()

	a := CanonicalPayload("POST", "/p", "", []byte("a"), "1", "n")
	b := CanonicalPayload("POST", "/p", "", []byte("b"), "1", "n")
	require.False(t, bytes.Equal(a, b))
}
