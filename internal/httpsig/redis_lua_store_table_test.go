package httpsig

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestNewRedisLuaNonceStoreDefaults(t *testing.T) {
	t.Parallel()

	// timeout<=0 -> 默认 3 秒；prefix 为空 -> 默认 httpsig:nonce.
	store := NewRedisLuaNonceStore(redis.NewClient(&redis.Options{}), "", 0)
	require.NotNil(t, store)
	require.Equal(t, 3*time.Second, store.timeout)
	require.Equal(t, "httpsig:nonce", store.prefix)
	require.Equal(t, "httpsig:nonce:index", store.indexKey)

	store = NewRedisLuaNonceStore(redis.NewClient(&redis.Options{}), "custom", time.Second)
	require.Equal(t, "custom", store.prefix)
	require.Equal(t, "custom:index", store.indexKey)
	require.Equal(t, time.Second, store.timeout)
}

func TestRedisLuaNonceStorePrefixed(t *testing.T) {
	t.Parallel()

	withPrefix := &RedisLuaNonceStore{prefix: "ns"}
	require.Equal(t, "ns:abc", withPrefix.prefixed("abc"))

	noPrefix := &RedisLuaNonceStore{prefix: ""}
	require.Equal(t, "abc", noPrefix.prefixed("abc"))
}

func TestRedisLuaNonceStoreUseTTLExpired(t *testing.T) {
	t.Parallel()

	client := newFakeEvalClient()
	store := &RedisLuaNonceStore{client: client, prefix: "nonce", timeout: time.Second, indexKey: "nonce:index"}

	ok, err := store.Use(context.Background(), "abc", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.False(t, ok)
	require.Nil(t, client.lastCtx)
}

// errEvalClient 让 Eval 返回错误，覆盖错误路径.
type errEvalClient struct {
	err error
}

func (c errEvalClient) Eval(ctx context.Context, _ string, _ []string, _ ...any) *redis.Cmd {
	cmd := redis.NewCmd(ctx)
	cmd.SetErr(c.err)
	return cmd
}

func TestRedisLuaNonceStoreUseClientError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("eval boom")
	store := &RedisLuaNonceStore{client: errEvalClient{err: wantErr}, prefix: "nonce", timeout: time.Second, indexKey: "nonce:index"}

	ok, err := store.Use(context.Background(), "abc", time.Now().Add(time.Minute))
	require.ErrorIs(t, err, wantErr)
	require.False(t, ok)
}

func TestRedisLuaNonceStoreUseNilContext(t *testing.T) {
	t.Parallel()

	client := newFakeEvalClient()
	store := &RedisLuaNonceStore{client: client, prefix: "nonce", timeout: time.Second, indexKey: "nonce:index"}

	//nolint:staticcheck // SA1012: 故意测试 nil context 的兜底分支
	ok, err := store.Use(nil, "abc", time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
}

// cleanupClient 同时实现 Eval 与 ZRemRangeByScore，用于覆盖 Cleanup 成功分支.
type cleanupClient struct {
	fakeEvalClient
	lastZRemKey string
	lastMin     string
	lastMax     string
	zremErr     error
}

func (c *cleanupClient) ZRemRangeByScore(ctx context.Context, key, minScore, maxScore string) *redis.IntCmd {
	c.lastZRemKey = key
	c.lastMin = minScore
	c.lastMax = maxScore
	cmd := redis.NewIntCmd(ctx)
	if c.zremErr != nil {
		cmd.SetErr(c.zremErr)
		return cmd
	}
	cmd.SetVal(1)
	return cmd
}

func TestRedisLuaNonceStoreCleanupSupported(t *testing.T) {
	t.Parallel()

	client := &cleanupClient{}
	store := &RedisLuaNonceStore{client: client, prefix: "nonce", timeout: time.Second, indexKey: "nonce:index"}

	before := time.UnixMilli(1_710_000_000_000)
	err := store.Cleanup(context.Background(), before)
	require.NoError(t, err)
	require.Equal(t, "nonce:index", client.lastZRemKey)
	require.Equal(t, "-inf", client.lastMin)
	require.Equal(t, "1710000000000", client.lastMax)
}

func TestRedisLuaNonceStoreCleanupError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("zrem boom")
	client := &cleanupClient{zremErr: wantErr}
	store := &RedisLuaNonceStore{client: client, prefix: "nonce", timeout: time.Second, indexKey: "nonce:index"}

	err := store.Cleanup(context.Background(), time.Now())
	require.ErrorIs(t, err, wantErr)
}

func TestRedisLuaNonceStoreCleanupUnsupported(t *testing.T) {
	t.Parallel()

	// fakeEvalClient 未实现 ZRemRangeByScore，Cleanup 应安全返回 nil.
	client := newFakeEvalClient()
	store := &RedisLuaNonceStore{client: client, prefix: "nonce", timeout: time.Second, indexKey: "nonce:index"}

	err := store.Cleanup(context.Background(), time.Now())
	require.NoError(t, err)
}
