package httpsig

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestNewRedisNonceStoreDefaults(t *testing.T) {
	t.Parallel()

	// timeout <= 0 时使用默认 3 秒.
	store := NewRedisNonceStore(redis.NewClient(&redis.Options{}), "p", 0)
	require.NotNil(t, store)
	require.Equal(t, 3*time.Second, store.timeout)
	require.Equal(t, "p", store.prefix)

	store = NewRedisNonceStore(redis.NewClient(&redis.Options{}), "p", time.Second)
	require.Equal(t, time.Second, store.timeout)
}

func TestRedisNonceStorePrefixed(t *testing.T) {
	t.Parallel()

	withPrefix := &RedisNonceStore{prefix: "ns"}
	require.Equal(t, "ns:abc", withPrefix.prefixed("abc"))

	noPrefix := &RedisNonceStore{prefix: ""}
	require.Equal(t, "abc", noPrefix.prefixed("abc"))
}

func TestRedisNonceStoreUseTTLExpired(t *testing.T) {
	t.Parallel()

	client := newFakeSetNXClient()
	store := &RedisNonceStore{client: client, prefix: "nonce", timeout: time.Second}

	// expiresAt 已过去 -> ttl<=0，直接返回 false 且不调用 client.
	ok, err := store.Use(context.Background(), "abc", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.False(t, ok)
	require.Nil(t, client.lastCtx)
}

// errSetNXClient 让 SetNX 返回错误，覆盖错误路径.
type errSetNXClient struct {
	err error
}

func (c errSetNXClient) SetNX(ctx context.Context, _ string, _ any, _ time.Duration) *redis.BoolCmd {
	cmd := redis.NewBoolCmd(ctx)
	cmd.SetErr(c.err)
	return cmd
}

func TestRedisNonceStoreUseClientError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("redis boom")
	store := &RedisNonceStore{client: errSetNXClient{err: wantErr}, prefix: "nonce", timeout: time.Second}

	ok, err := store.Use(context.Background(), "abc", time.Now().Add(time.Minute))
	require.ErrorIs(t, err, wantErr)
	require.False(t, ok)
}

func TestRedisNonceStoreUseNilContext(t *testing.T) {
	t.Parallel()

	client := newFakeSetNXClient()
	store := &RedisNonceStore{client: client, prefix: "nonce", timeout: time.Second}

	//nolint:staticcheck // SA1012: 故意测试 nil context 的兜底分支
	ok, err := store.Use(nil, "abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
}
