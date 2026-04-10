package httpsig

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type stubVerifier struct {
	calls int
}

type contextKey string

func (v *stubVerifier) Verify(_ []byte, signed string) (bool, error) {
	v.calls++
	return signed == "kid.ok", nil
}

type recordingNonceStore struct {
	calls int
	keys  map[string]time.Time
	now   func() time.Time
	last  context.Context
}

func (s *recordingNonceStore) Use(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	s.calls++
	s.last = ctx
	if s.keys == nil {
		s.keys = make(map[string]time.Time)
	}
	current := time.Now
	if s.now != nil {
		current = s.now
	}
	if deadline, ok := s.keys[key]; ok && current().Before(deadline) {
		return false, nil
	}
	s.keys[key] = expiresAt
	return true, nil
}

func TestVerifyRequestDoesNotConsumeNonceOnInvalidSignature(t *testing.T) {
	now := time.Unix(1_710_000_000, 0)
	headers := Headers{
		Signature: "kid.bad",
		Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce:     "nonce-1",
	}

	verifier := &stubVerifier{}
	store := &recordingNonceStore{now: func() time.Time { return now }}
	opts := VerifyOptions{
		Now:          func() time.Time { return now },
		MaxSkew:      time.Minute,
		Nonces:       store,
		MaxBodyBytes: 1024,
	}

	ctx := context.WithValue(context.Background(), contextKey("request-id"), "req-1")

	err := VerifyRequest(ctx, verifier, "POST", "/callbacks/order-paid", "", []byte(`{"ok":true}`), headers, opts)
	require.ErrorIs(t, err, ErrSignatureInvalid)
	require.Equal(t, 1, verifier.calls)
	require.Zero(t, store.calls)

	headers.Signature = "kid.ok"
	err = VerifyRequest(ctx, verifier, "POST", "/callbacks/order-paid", "", []byte(`{"ok":true}`), headers, opts)
	require.NoError(t, err)
	require.Equal(t, 2, verifier.calls)
	require.Equal(t, 1, store.calls)
	require.Same(t, ctx, store.last)

	err = VerifyRequest(ctx, verifier, "POST", "/callbacks/order-paid", "", []byte(`{"ok":true}`), headers, opts)
	require.ErrorIs(t, err, ErrReplayDetected)
	require.Equal(t, 2, store.calls)
}
