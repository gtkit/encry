# Redis 防重放 NonceStore（文档示例）

> 本库**不再依赖 `go-redis`**（避免把可选的 Redis 能力塞进每个使用者的依赖图）。
> 内置只保留 `httpsig.NewMemoryNonceStore()`（单进程/示例用）。多实例部署需要分布式
> 防重放时，请在你的项目里**自行实现 `NonceStore` 接口**——下面给出 Redis 版参考实现。

`NonceStore` 接口（仓内 `internal/httpsig`，外部按相同签名实现即可）：

```go
// Use 原子性地"占用"一个 (timestamp+nonce) 键；首次返回 true，重复返回 false。
type NonceStore interface {
    Use(ctx context.Context, key string, expiresAt time.Time) (bool, error)
}
```

## Redis 实现（SET NX + 过期，copy 到你的项目）

```go
type RedisNonceStore struct {
    client  redis.Cmdable
    prefix  string
    timeout time.Duration
}

func NewRedisNonceStore(client redis.Cmdable, prefix string, timeout time.Duration) *RedisNonceStore {
    return &RedisNonceStore{client: client, prefix: prefix, timeout: timeout}
}

func (s *RedisNonceStore) Use(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
    ttl := time.Until(expiresAt)
    if ttl <= 0 {
        ttl = s.timeout
    }
    // SET key 1 NX EX <ttl>：键不存在才写入并返回 true（首次使用）；已存在返回 false（重放）。
    ok, err := s.client.SetNX(ctx, s.prefix+":"+key, 1, ttl).Result()
    if err != nil {
        return false, err
    }
    return ok, nil
}
```

接入中间件（net/http 版仍在 `internal/middleware`，标准库实现）：

```go
handler := middleware.HTTPVerifyRequestMiddleware(service, httpsig.VerifyOptions{
    MaxSkew:      5 * time.Minute,
    Nonces:       NewRedisNonceStore(redisClient, "encry:httpsig:nonce", 2*time.Second),
    MaxBodyBytes: 1 << 20,
})(mux)
```

> 说明：`internal/httpsig`、`internal/middleware`、`internal/signer`、`internal/keyring` 为仓库内部包，
> 外部不可 `import`；以上为参考模式。生产中你可以基于自己的签名/密钥栈与上面的 `RedisNonceStore` 组合实现。
