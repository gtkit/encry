# encry

`encry` 是一个面向 Go 1.26 的常用加密、摘要、签名工具包集合。

当前仓库同时包含两类能力：

- 现代默认能力：`AES-GCM`、`SHA224/256/384/512`、`RSA-OAEP`、`RSA-PSS`、`Ed25519`
- 兼容历史协议能力：`AES-CBC/CFB`、`RSA PKCS#1 v1.5`、`RC4`、`MD5`、`SHA1`

如果是新系统，优先使用现代默认能力。

## 安装

```bash
go get github.com/gtkit/encry
```

## 目录

| 目录 | 能力 | 说明 |
| --- | --- | --- |
| `aes` | `AES-CBC`、`AES-CFB`、`AES-GCM` | 新系统优先 `GCM` |
| `sha256` | `SHA224`、`SHA256`、`SHA384`、`SHA512` | 摘要、文件摘要、摘要校验 |
| `rsa` | `PKCS#1 v1.5`、`OAEP`、`PSS` | 兼容旧协议与现代 RSA 场景 |
| `ed` | `Ed25519` | 密钥生成、PEM、签名验签 |
| `hmac` | `HMAC-SHA1`、`HMAC-SHA256` | 消息认证 |
| `hash` | `bcrypt`、`argon2`、`fnv` | 密码哈希与辅助散列 |
| `jwt` | `HMAC JWT`、`Ed25519 JWT` | Token 生成与解析 |
| `md5` | `MD5` | 兼容旧系统 |
| `sha1` | `SHA1` | 兼容旧系统 |
| `rc4` | `RC4` | 兼容旧系统 |

## 推荐用法

### AES-GCM

```go
package main

import (
	"fmt"

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

	fmt.Println(string(plainText))
}
```

### SHA256+

```go
package main

import (
	"fmt"

	encrysha256 "github.com/gtkit/encry/sha256"
)

func main() {
	fmt.Println(encrysha256.String("hello"))
	fmt.Println(encrysha256.String512("hello"))
}
```

### RSA-OAEP

```go
package main

import (
	"fmt"

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

	fmt.Println(string(plainText))
}
```

### RSA-PSS

```go
package main

import (
	"fmt"

	"github.com/gtkit/encry/rsa"
)

func main() {
	_ = rsa.GenerateRsaKey(2048, "./keys")

	signature, err := rsa.SignPSSBase64([]byte("hello-pss"), "./keys/private.pem")
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPSSBase64([]byte("hello-pss"), "./keys/public.pem", signature)
	fmt.Println(err == nil)
}
```

### Ed25519

```go
package main

import (
	"fmt"

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

	fmt.Println(ed.VerifyBase64(publicKey, []byte("hello-ed25519"), signature))
}
```

## 兼容算法说明

下列能力保留是为了兼容旧系统，不建议作为新协议默认选型：

- `md5`
- `sha1`
- `rc4`
- `rsa` 下的 `PKCS#1 v1.5`
- `aes` 下的 `CBC`、`CFB`

如果你在新服务里需要默认安全方案，优先使用：

- 对称加密：`AES-GCM`
- 摘要：`SHA256` 及以上
- 非对称加密：`RSA-OAEP`
- 非对称签名：`RSA-PSS` 或 `Ed25519`

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
go run ./examples/gin_middleware
go run ./examples/service_aes_gcm
go run ./examples/service_ed25519_rotation
go run ./examples/service_rsa_pss_rotation
```

示例说明见 [examples/README.md](/Users/xiaozhaofu/go/src/encry/examples/README.md)。

## 内部结构

如果你想把这些模板继续抽到业务项目里，仓库里现在已经有一套可复用的内部结构：

- `internal/cryptoenv`
  负责环境变量和默认 key 目录配置
- `internal/keyring`
  负责 `kid -> key` 的快照、切换、metadata、生命周期和 JWKS-like 公钥发布
- `internal/sealer`
  负责基于 `kid` 的 `AES-GCM` 加解密服务
- `internal/signer`
  负责基于 `kid` 的 `Ed25519`、`RSA-PSS` 签名验签服务
- `internal/middleware`
  负责 `net/http` 和 `Gin` 的签名校验中间件

这几个包已经被 `examples/service_*` 模板直接复用。

## 验证

```bash
go test ./...
go test -race ./...
go vet ./...
```
