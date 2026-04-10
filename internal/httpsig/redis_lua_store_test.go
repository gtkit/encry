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
	lastCtx   context.Context
}

func newFakeEvalClient() *fakeEvalClient {
	return &fakeEvalClient{
		nonceKeys: make(map[string]time.Time),
		index:     make(map[string]time.Time),
	}
}

func (f *fakeEvalClient) Eval(ctx context.Context, _ string, keys []string, args ...any) *redis.Cmd {
	f.lastCtx = ctx
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
	if err := ctx.Err(); err != nil {
		cmd.SetErr(err)
		return cmd
	}
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
	client := newFakeEvalClient()
	store := &RedisLuaNonceStore{
		client:   client,
		prefix:   "nonce",
		timeout:  time.Second,
		indexKey: "nonce:index",
	}

	ok, err := store.Use(context.Background(), "abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, client.lastCtx)

	ok, err = store.Use(context.Background(), "abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRedisLuaNonceStoreUseHonorsParentContext(t *testing.T) {
	client := newFakeEvalClient()
	store := &RedisLuaNonceStore{
		client:   client,
		prefix:   "nonce",
		timeout:  time.Second,
		indexKey: "nonce:index",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := store.Use(ctx, "abc", time.Now().Add(time.Minute))
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, ok)
	require.NotNil(t, client.lastCtx)
	require.ErrorIs(t, client.lastCtx.Err(), context.Canceled)
}
