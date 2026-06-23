# encry

`encry` 是一个面向 Go 1.26 的常用加密、摘要、签名工具包集合。

当前仓库同时包含两类能力：

- 现代默认能力：`AES-GCM`、`SHA224/256/384/512`、`RSA-OAEP`、`RSA-PSS`、`Ed25519`
- 兼容历史协议能力：`AES-CBC/CFB`、`RC4`、`MD5`、`SHA1`

如果是新系统，优先使用现代默认能力。

## 安装

```bash
go get github.com/gtkit/encry
```

## API 边界

本仓库承诺的公共 API，仅限顶层非 `internal/`、非 `examples/` 的 Go 包。

- 可以直接依赖：顶层算法与工具包，例如 `aes`、`rsa`、`ed`、`sha256`、`hmac`、`hash`
- 不属于公共 API：`internal/...`，仅供仓库内部实现和示例复用，不承诺兼容性
- 不属于公共 API：`examples/...` 与 `examples/internal/...`，仅用于演示、模板和编译校验，不建议在业务代码里直接导入

如果你要在业务项目里落地示例中的服务编排方式，建议参考示例实现后在业务仓库内自行封装，而不是直接依赖这些私有包。

## 目录

| 目录 | 能力 | 说明 |
| --- | --- | --- |
| `aes` | `AES-CBC`、`AES-CFB`、`AES-GCM` | 新系统优先 `GCM` |
| `sha256` | `SHA224`、`SHA256`、`SHA384`、`SHA512` | 摘要、文件摘要、摘要校验 |
| `rsa` | `OAEP`、`PSS`、`PKCS#1 PEM` | 加密用 OAEP、签名用 PSS；兼容 PKCS#1 PEM 密钥格式 |
| `ed` | `Ed25519` | 密钥生成、PEM、签名验签 |
| `ecdsa` | `ECDSA` | P-256/384 签名验签、PEM |
| `hmac` | `HMAC-SHA1`、`HMAC-SHA256` | 消息认证 |
| `hash` | `bcrypt`、`argon2`、`fnv` | 密码哈希与辅助散列 |
| `chacha` | `XChaCha20-Poly1305` | 现代 AEAD，无 AES-NI 依赖 |
| `stream` | `XChaCha20-Poly1305` STREAM | 大文件流式 AEAD（io.Reader/Writer，抗截断/重排） |
| `ecdh` | `X25519`、`NIST ECDH` | 密钥协商 |
| `hkdf` | `HKDF` | 密钥派生（RFC5869） |
| `hpke` | `HPKE`（RFC9180） | 混合公钥加密，加密到公钥 |
| `mlkem` | `ML-KEM-768` | 后量子密钥封装（FIPS 203） |
| `md5` | `MD5` | 兼容旧系统 |
| `sha1` | `SHA1` | 兼容旧系统 |
| `rc4` | `RC4` | 兼容旧系统 |

> 现代原语（`chacha`/`ecdh`/`ecdsa`/`hkdf`/`hpke`/`mlkem`）基于 go1.26 标准库（`hpke` 为 1.26 新增）。
> 需要"加密一段数据发给某公钥持有者"时，优先用 `hpke`（无 RSA 的明文长度限制）；
> 需要双方协商对称密钥用 `ecdh` + `hkdf`；面向后量子用 `mlkem`。

## 推荐用法

### AES-GCM

```go
package main

import (
	"log"

	"github.com/gtkit/encry/aes"
)

func main() {
	gcm := aes.NewGCM("IgkibX71IEf382PT")

	cipherText, err := gcm.EncryptWithAAD([]byte("hello-gcm"), []byte("order:1001"))
	if err != nil {
		panic(err)
	}

	plainText, err := gcm.DecryptWithAAD(cipherText, []byte("order:1001"))
	if err != nil {
		panic(err)
	}

	log.Println(string(plainText))
}
```

### SHA256+

```go
package main

import (
	"log"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func main() {
	log.Println(encrysha256.String("hello"))
	log.Println(encrysha256.String512("hello"))
}
```

### RSA-OAEP

```go
package main

import (
	"log"

	"github.com/gtkit/encry/rsa"
)

func main() {
	_ = rsa.GenerateRsaKey(2048, "./keys")

	cipherText, err := rsa.EncryptOAEPBase64([]byte("hello-oaep"), "./keys/public.pem")
	if err != nil {
		panic(err)
	}

	plainText, err := rsa.DecryptOAEPBase64(cipherText, "./keys/private.pem")
	if err != nil {
		panic(err)
	}

	log.Println(string(plainText))
}
```

### RSA-PSS

```go
package main

import (
	"log"

	"github.com/gtkit/encry/rsa"
)

func main() {
	_ = rsa.GenerateRsaKey(2048, "./keys")

	signature, err := rsa.SignPSSBase64([]byte("hello-pss"), "./keys/private.pem")
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPSSBase64([]byte("hello-pss"), "./keys/public.pem", signature)
	log.Println(err == nil)
}
```

### Ed25519

```go
package main

import (
	"log"

	"github.com/gtkit/encry/ed"
)

func main() {
	publicKey, privateKey, err := ed.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	signature, err := ed.SignBase64(privateKey, []byte("hello-ed25519"))
	if err != nil {
		panic(err)
	}

	log.Println(ed.VerifyBase64(publicKey, []byte("hello-ed25519"), signature))
}
```

### Argon2 密码哈希

零配置：只传明文即可，使用安全默认参数（argon2id, t=3, m=64MB, p=4），输出 PHC 标准串。

```go
package main

import (
	"log"

	"github.com/gtkit/encry/hash"
)

func main() {
	encoded, err := hash.Argon2HashPassword("s3cr3t")
	if err != nil {
		panic(err)
	}

	log.Println(hash.Argon2VerifyPassword("s3cr3t", encoded)) // true
}
```

需要调参时用 Functional Options：

```go
a := hash.NewArgon2(
	hash.WithMemory(32*1024), // 32MB
	hash.WithTime(2),
)

encoded, _ := a.Hash("s3cr3t")
log.Println(a.Verify("s3cr3t", encoded)) // true
```

## 兼容算法说明

下列能力保留是为了兼容旧系统，不建议作为新协议默认选型：

- `md5`
- `sha1`
- `rc4`
- `aes` 下的 `CBC`、`CFB`

如果你在新服务里需要默认安全方案，优先使用：

- 对称加密：`AES-GCM`
- 摘要：`SHA256` 及以上
- 非对称加密：`RSA-OAEP`
- 非对称签名：`RSA-PSS` 或 `Ed25519`

> 大数据加密提示：RSA 单块/分段（`EncryptOAEPChunked` 等）直接加密大块数据是反模式、效率低。
> 正确做法是混合加密——用随机 AES key 以 `AES-GCM` 加密数据，再用 `RSA-OAEP` 加密这把 AES key 一并传输。

## 可运行示例

仓库已经补了 `examples/` 目录，可以直接运行：

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
go run ./examples/service_aes_gcm
go run ./examples/service_ed25519_rotation
go run ./examples/service_rsa_pss_rotation
```

示例说明见 [examples/README.md](/Users/xiaozhaofu/go/src/encry/examples/README.md)。

> ⚠️ 关于密钥轮转 / 请求签名中间件 / JWKS 类示例（`jwks_publish`、`http_middleware*`、`gin_middleware`、`service_*`）：
> 它们演示的是仓库内部 `internal/`（keyring、httpsig、sealer、signer、middleware）的能力。
> 按 Go 的 internal 规则，**这些包仅供本模块内部使用，外部项目无法 `import`**。
> 这些示例是面向本仓维护者的参考实现，不属于对外公开 API；外部使用者请使用顶层公开包
> （`aes`、`rsa`、`ed`、`ecdsa`、`hpke`、`mlkem`、`chacha`、`ecdh`、`hkdf`、`hmac`、`hash`、`sha256` 等）。
>
> 注：本库**不依赖 gin**。原 gin 中间件示例已转为文档 [`examples/gin_middleware/README.md`](examples/gin_middleware/README.md)（HTTP 中间件以标准库 `net/http` 实现）。

## 构建边界

`examples/...` 是仓库内的独立示例包。

- 它们会被 `go test ./...`、`go build ./...` 这类全仓命令枚举并编译检查
- 它们不会自动链接进你的生产二进制，除非你显式构建或导入这些包

推荐把生产校验和示例校验分开执行：

```bash
make verify-prod
make lint-prod
make check-secure-prod
make test-examples
make build-examples
make lint-examples
```

## 内部结构

如果你想参考这些模板在业务项目里落地，仓库里保留了一组仅供仓库内部和示例复用的私有包：

- `internal/keyring`
  负责 `kid -> key` 的快照、切换、metadata、生命周期和 JWKS-like 公钥发布
- `internal/sealer`
  负责基于 `kid` 的 `AES-GCM` 加解密服务
- `internal/signer`
  负责基于 `kid` 的 `Ed25519`、`RSA-PSS` 签名验签服务
- `internal/httpsig`
  负责 `method + path + query + body digest + timestamp + nonce` 的规范化请求签名
- `internal/middleware`
  负责 `net/http` 和 `Gin` 的签名校验中间件与防重放接入

示例共享的配置辅助逻辑位于 `examples/internal/cryptoenv`，不属于根模块公共 API。

## 请求签名协议

仓库里现在已经有一套更适合 webhook / callback / service-to-service 场景的规范化请求签名协议：

- 头字段：
  `X-Signature`
  `X-Signature-Timestamp`
  `X-Signature-Nonce`
- canonical string：
  `METHOD`
  `PATH`
  `RAW_QUERY`
  `TIMESTAMP`
  `NONCE`
  `SHA256(body)`

对应实现见：

- `internal/httpsig`
- `internal/middleware`
- `examples/http_middleware`
- `examples/gin_middleware`

如果要把防重放扩展到多实例部署，仓库里现在也有：

- `internal/httpsig.RedisNonceStore`
- `internal/httpsig.RedisLuaNonceStore`
- `examples/http_middleware_redis`

## 验证

```bash
make verify-prod
make lint-prod
make check-secure-prod
make test-examples
make build-examples
make lint-examples
```

如果你只是想做一次全仓 smoke test，仍然可以运行：

```bash
make test
```
