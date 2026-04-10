package httpsig

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type fakeSetNXClient struct {
	keys    map[string]time.Time
	lastCtx context.Context
}

func newFakeSetNXClient() *fakeSetNXClient {
	return &fakeSetNXClient{keys: make(map[string]time.Time)}
}

func (f *fakeSetNXClient) SetNX(ctx context.Context, key string, _ any, expiration time.Duration) *redis.BoolCmd {
	f.lastCtx = ctx
	now := time.Now()
	for k, deadline := range f.keys {
		if !now.Before(deadline) {
			delete(f.keys, k)
		}
	}

	cmd := redis.NewBoolCmd(ctx)
	if err := ctx.Err(); err != nil {
		cmd.SetErr(err)
		return cmd
	}
	if deadline, ok := f.keys[key]; ok && now.Before(deadline) {
		cmd.SetVal(false)
		return cmd
	}
	f.keys[key] = now.Add(expiration)
	cmd.SetVal(true)
	return cmd
}

func TestRedisNonceStoreUse(t *testing.T) {
	client := newFakeSetNXClient()
	store := &RedisNonceStore{
		client:  client,
		prefix:  "nonce",
		timeout: time.Second,
	}

	ok, err := store.Use(context.Background(), "abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, client.lastCtx)

	ok, err = store.Use(context.Background(), "abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRedisNonceStoreUseHonorsParentContext(t *testing.T) {
	client := newFakeSetNXClient()
	store := &RedisNonceStore{
		client:  client,
		prefix:  "nonce",
		timeout: time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := store.Use(ctx, "abc", time.Now().Add(time.Minute))
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, ok)
	require.NotNil(t, client.lastCtx)
	require.ErrorIs(t, client.lastCtx.Err(), context.Canceled)
}
