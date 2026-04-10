# examples

这些示例都可以直接运行，但它们不属于根模块的公共 API。

`examples/...` 是独立 package，会被 `go test ./...` 枚举并编译检查，但不会自动链接进生产二进制。

推荐把生产校验和示例校验分开执行：

```bash
make verify-prod
make lint-prod
make check-secure-prod
make test-examples
make build-examples
make lint-examples
```

```bash
go run ./examples/aes_gcm
go run ./examples/aes_gcm_aad
go run ./examples/sha256
go run ./examples/sha256_file
go run ./examples/rsa_oaep
go run ./examples/rsa_oaep_label
go run ./examples/rsa_pss
go run ./examples/rsa_pss_options
go run ./examples/ed25519
go run ./examples/ed25519_files
go run ./examples/jwks_publish
go run ./examples/http_middleware
go run ./examples/http_middleware_redis
go run ./examples/gin_middleware
go run ./examples/service_aes_gcm
go run ./examples/service_ed25519_rotation
go run ./examples/service_rsa_pss_rotation
```

说明：

- `aes_gcm`：最小 `AES-GCM` 加解密示例
- `aes_gcm_aad`：演示业务上下文 `AAD`
- `sha256`：最小 `SHA224/256/384/512` 示例
- `sha256_file`：演示文件摘要与校验
- `rsa_oaep`：最小 `RSA-OAEP` 加解密示例
- `rsa_oaep_label`：演示 `OAEP label` 绑定业务场景
- `rsa_pss`：最小 `RSA-PSS` 签名验签示例
- `rsa_pss_options`：演示 `PSSOptions` 和 `SHA512`
- `ed25519`：最小 `Ed25519` 签名验签示例
- `ed25519_files`：演示 PEM 文件落盘和业务目录约定
- `jwks_publish`：演示 metadata、生命周期状态和公钥发布
- `http_middleware`：演示 `net/http` 规范化请求签名中间件
- `http_middleware_redis`：演示 `Redis` 防重放 nonce store
- `gin_middleware`：演示 `Gin` 规范化请求签名中间件
- `service_aes_gcm`：服务端 `config + key path + kid rotate + AAD`
- `service_ed25519_rotation`：服务端 `config + key path + kid rotate + verify old signatures`
- `service_rsa_pss_rotation`：服务端 `config + key path + kid rotate + PSS options`

这些服务模板内部复用了仓库新增的内部包：

- `examples/internal/cryptoenv`：读取环境变量和示例默认配置
- `internal/keyring`：管理 `kid -> key` 的原子快照
- `internal/keyring`：现在还包含 `metadata/lifecycle/JWKS-like` 能力
- `internal/sealer`：封装 `AES-GCM` 的 `kid` 路由
- `internal/signer`：封装 `Ed25519` 与 `RSA-PSS` 的签名验签服务
- `internal/middleware`：封装 `net/http` 与 `Gin` 验签中间件

规范化请求签名默认使用这些头：

- `X-Signature`
- `X-Signature-Timestamp`
- `X-Signature-Nonce`

规范化签名串由以下字段按换行拼接：

- `METHOD`
- `PATH`
- `RAW_QUERY`
- `TIMESTAMP`
- `NONCE`
- `SHA256(body)`
