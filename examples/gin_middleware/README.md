# Gin 请求签名中间件（文档示例）

> 本库**不再依赖 gin**（避免把 Web 框架及其大量传递依赖塞进每个使用者的依赖图）。
> 本目录原先的可运行 `main.go` 已转为文档：下面的代码作为**参考实现**保留，演示如何在 gin 中
> 校验带签名的请求（含时间窗口 + 防重放）。

> 说明：示例引用的 `internal/httpsig`、`internal/keyring`、`internal/signer` 属仓库**内部包**，
> 外部项目无法直接 import；以下代码是**仓内参考**，外部使用者请按相同思路自行实现一个
> `gin.HandlerFunc`（读取 body → 还原 body → 调用你的验签逻辑 → 失败则 `c.AbortWithStatusJSON`）。

## 自定义 gin 验签中间件的骨架

```go
// VerifyRequest 在你的项目里基于自己的验签器实现一个 gin 中间件。
// verify 形如 func(method, path, query string, body []byte, headers http.Header) (bool, error)
func VerifyRequest(maxBody int64, verify VerifyFunc) gin.HandlerFunc {
    return func(c *gin.Context) {
        body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody+1))
        if err != nil {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "read body failed"})
            return
        }
        if int64(len(body)) > maxBody {
            c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
            return
        }
        // 还原 body 供下游处理器读取
        c.Request.Body = io.NopCloser(bytes.NewReader(body))

        ok, err := verify(c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery, body, c.Request.Header)
        if err != nil || !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "signature verification failed"})
            return
        }
        c.Next()
    }
}
```

## 仓内参考：用内部签名栈搭建（演示用，外部不可 import）

```go
ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
records, _ := keyring.LoadEd25519KeyPairRecords(keyDir)
_ = ring.Store(activeKID, records)
service := signer.NewManagedEd25519(ring)
nonceStore := httpsig.NewMemoryNonceStore()

router := gin.New()
router.Use(func(c *gin.Context) {
    body, err := io.ReadAll(c.Request.Body)
    if err != nil {
        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "read body failed"})
        return
    }
    c.Request.Body = io.NopCloser(bytes.NewReader(body))

    if err := httpsig.VerifyRequest(
        c.Request.Context(), service,
        c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery, body,
        httpsig.FromHTTP(c.Request.Header),
        httpsig.VerifyOptions{MaxSkew: 5 * time.Minute, Nonces: nonceStore, MaxBodyBytes: 1 << 20},
    ); err != nil {
        c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }
    c.Next()
})
router.POST("/callbacks/order-paid", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "accepted"})
})
```

请求签名端可参考 `httpsig.SignRequest(...)` 生成 `X-Signature`/`X-Signature-Timestamp`/`X-Signature-Nonce` 头。
对应的 net/http 版本仍在 `internal/middleware` 中以标准库实现（无第三方依赖）。
