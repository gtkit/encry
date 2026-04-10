package httpsig

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisEvalClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
}

// RedisLuaNonceStore 使用 Lua 脚本实现带过期索引的 nonce 存储.
//
// 设计目标：
// - 使用单个脚本保证「清理旧索引 + 检查重放 + 写入 nonce + 写入索引」原子完成
// - 兼容多实例部署场景
// - 保留一个 zset 作为观测和批量清理入口
type RedisLuaNonceStore struct {
	client   redisEvalClient
	prefix   string
	timeout  time.Duration
	indexKey string
}

const redisNonceUseScript = `
local nonceKey = KEYS[1]
local indexKey = KEYS[2]
local nowMs = tonumber(ARGV[1])
local expiresAtMs = tonumber(ARGV[2])
local ttlMs = tonumber(ARGV[3])

local expired = redis.call("ZRANGEBYSCORE", indexKey, "-inf", nowMs)
for _, key in ipairs(expired) do
  redis.call("DEL", key)
end
if #expired > 0 then
  redis.call("ZREMRANGEBYSCORE", indexKey, "-inf", nowMs)
end

if redis.call("EXISTS", nonceKey) == 1 then
  return 0
end

redis.call("PSETEX", nonceKey, ttlMs, "1")
redis.call("ZADD", indexKey, expiresAtMs, nonceKey)
return 1
`

// NewRedisLuaNonceStore 创建一个脚本化 Redis nonce store.
func NewRedisLuaNonceStore(client redis.Cmdable, prefix string, timeout time.Duration) *RedisLuaNonceStore {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if prefix == "" {
		prefix = "httpsig:nonce"
	}
	return &RedisLuaNonceStore{
		client:   client,
		prefix:   prefix,
		timeout:  timeout,
		indexKey: prefix + ":index",
	}
}

// Use 通过 Lua 脚本原子完成 nonce 占用.
func (s *RedisLuaNonceStore) Use(key string, expiresAt time.Time) (bool, error) {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	now := time.Now()
	cmd := s.client.Eval(
		ctx,
		redisNonceUseScript,
		[]string{s.prefixed(key), s.indexKey},
		now.UnixMilli(),
		expiresAt.UnixMilli(),
		ttl.Milliseconds(),
	)
	result, err := cmd.Int64()
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

// Cleanup 清理 zset 中已过期的索引项.
func (s *RedisLuaNonceStore) Cleanup(ctx context.Context, before time.Time) error {
	if remover, ok := s.client.(interface {
		ZRemRangeByScore(ctx context.Context, key, minScore, maxScore string) *redis.IntCmd
	}); ok {
		return remover.ZRemRangeByScore(ctx, s.indexKey, "-inf", fmt.Sprintf("%d", before.UnixMilli())).Err()
	}
	return nil
}

func (s *RedisLuaNonceStore) prefixed(key string) string {
	if s.prefix == "" {
		return key
	}
	return s.prefix + ":" + key
}
