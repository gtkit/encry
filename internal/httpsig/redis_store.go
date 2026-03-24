package httpsig

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type setNXClient interface {
	SetNX(ctx context.Context, key string, value any, expiration time.Duration) *redis.BoolCmd
}

// RedisNonceStore 使用 Redis SET NX + TTL 实现防重放 nonce 存储.
type RedisNonceStore struct {
	client  setNXClient
	prefix  string
	timeout time.Duration
}

// NewRedisNonceStore 创建一个 Redis nonce store.
func NewRedisNonceStore(client redis.Cmdable, prefix string, timeout time.Duration) *RedisNonceStore {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &RedisNonceStore{
		client:  client,
		prefix:  prefix,
		timeout: timeout,
	}
}

// Use 尝试占用一个 nonce key，利用 Redis 保证分布式幂等.
func (s *RedisNonceStore) Use(key string, expiresAt time.Time) (bool, error) {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	return s.client.SetNX(ctx, s.prefixed(key), "1", ttl).Result()
}

func (s *RedisNonceStore) prefixed(key string) string {
	if s.prefix == "" {
		return key
	}
	return s.prefix + ":" + key
}
