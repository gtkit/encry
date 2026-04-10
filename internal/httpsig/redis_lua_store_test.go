package httpsig

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type fakeEvalClient struct {
	nonceKeys map[string]time.Time
	index     map[string]time.Time
}

func newFakeEvalClient() *fakeEvalClient {
	return &fakeEvalClient{
		nonceKeys: make(map[string]time.Time),
		index:     make(map[string]time.Time),
	}
}

func (f *fakeEvalClient) Eval(ctx context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	nowMs, ok := args[0].(int64)
	if !ok {
		return redis.NewCmd(ctx)
	}
	expiresAtMs, ok := args[1].(int64)
	if !ok {
		return redis.NewCmd(ctx)
	}
	ttlMs, ok := args[2].(int64)
	if !ok {
		return redis.NewCmd(ctx)
	}

	now := time.UnixMilli(nowMs)
	for nonceKey, deadline := range f.nonceKeys {
		if !now.Before(deadline) {
			delete(f.nonceKeys, nonceKey)
			delete(f.index, nonceKey)
		}
	}

	cmd := redis.NewCmd(ctx)
	nonceKey := keys[0]
	if deadline, ok := f.nonceKeys[nonceKey]; ok && now.Before(deadline) {
		cmd.SetVal(int64(0))
		return cmd
	}

	f.nonceKeys[nonceKey] = time.UnixMilli(expiresAtMs)
	f.index[nonceKey] = time.UnixMilli(expiresAtMs)
	_ = ttlMs
	cmd.SetVal(int64(1))
	return cmd
}

func TestRedisLuaNonceStoreUse(t *testing.T) {
	store := &RedisLuaNonceStore{
		client:   newFakeEvalClient(),
		prefix:   "nonce",
		timeout:  time.Second,
		indexKey: "nonce:index",
	}

	ok, err := store.Use("abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = store.Use("abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.False(t, ok)
}
