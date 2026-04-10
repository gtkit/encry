package httpsig

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type fakeSetNXClient struct {
	keys map[string]time.Time
}

func newFakeSetNXClient() *fakeSetNXClient {
	return &fakeSetNXClient{keys: make(map[string]time.Time)}
}

func (f *fakeSetNXClient) SetNX(ctx context.Context, key string, _ any, expiration time.Duration) *redis.BoolCmd {
	now := time.Now()
	for k, deadline := range f.keys {
		if !now.Before(deadline) {
			delete(f.keys, k)
		}
	}

	cmd := redis.NewBoolCmd(ctx)
	if deadline, ok := f.keys[key]; ok && now.Before(deadline) {
		cmd.SetVal(false)
		return cmd
	}
	f.keys[key] = now.Add(expiration)
	cmd.SetVal(true)
	return cmd
}

func TestRedisNonceStoreUse(t *testing.T) {
	store := &RedisNonceStore{
		client:  newFakeSetNXClient(),
		prefix:  "nonce",
		timeout: time.Second,
	}

	ok, err := store.Use("abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = store.Use("abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.False(t, ok)
}
