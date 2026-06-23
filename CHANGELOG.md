# Changelog

本项目变更遵循[语义化版本](https://semver.org/lang/zh-CN/)。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/)。

## [Unreleased]

## [v1.2.0] - 2026-06-23

本轮为一次较大的 API 整理与扩充（项目暂无下游使用者，故破坏性变更直接在 v1 内完成）。

### Added
- 新增现代加密原语公开包（基于 go1.26 标准库 / `golang.org/x/crypto`，无新增外部依赖）：
  - `chacha`：XChaCha20-Poly1305 AEAD。
  - `ecdh`：X25519 / NIST 椭圆曲线 Diffie-Hellman 密钥协商。
  - `ecdsa`：ECDSA 签名/验签与 PEM 序列化。
  - `hkdf`：RFC5869 HKDF 密钥派生。
  - `hpke`：RFC9180 混合公钥加密（`crypto/hpke`，go1.26 新增）。
  - `mlkem`：后量子密钥封装 ML-KEM-768（FIPS 203）。
  - `stream`：基于 `io.Reader`/`io.Writer` 的 STREAM 分块流式 AEAD，抗篡改/截断/重排。
- `rsa.GenerateKeyPairContext`：支持 `context` 取消的密钥生成。

### Changed
- **BREAKING** 非对称验签统一返回 `(bool, error)`（`ed`/`ecdsa`/`rsa`）：`bool` 表示是否有效，`error` 表示操作性失败；对称 MAC/摘要/口令校验仍返回 `bool`。
- **BREAKING** `hmac.Sha1ToHex`/`Sha1ToBase64` 参数由 `string` 改为 `[]byte`，与 `Sha256*` 一致。
- **BREAKING** `hmac.Sha256ToBase64` 由 URL 编码改为标准 Base64，与 `Sha1ToBase64` 一致。
- 依赖 `github.com/gtkit/json` 升级到 `github.com/gtkit/json/v2`。
- `hids` 包迁移到 `sqids`（`github.com/sqids/sqids-go`），替换停更的 `speps/go-hashids`。
- 为各包补充包级 GoDoc 注释与 Example。

### Removed
- **BREAKING** 移除冗余/遗留封装：
  - `base64`：`Encode`/`Decode`（与 `StdEncode`/`StdDecode` 同实现）。
  - `rc4`：别名 `New`/`Encrypt`/`Decrypt`（RC4 对称，统一用 `Apply`）。
  - `md5`/`sha1`：`New`（与 `String` 同实现）。
  - `rsa`：全部 PKCS#1 v1.5 加解密、分段（chunked）、MD5/SHA1 遗留签名 wrapper（仅保留 OAEP/PSS 与密钥/PEM 工具）。
  - `aes`：永不可用的 CBC 遗留随机 IV 回退路径。
- **BREAKING** 移除对 `github.com/gin-gonic/gin` 的依赖：删除 `internal/middleware` 的 gin 中间件（保留 `net/http` 版），gin 集成示例转为文档。

### Fixed
- `hash.GenerateRandomPassword` 修复取模偏置（改用拒绝采样）。
- `stream` 增加分块计数器溢出保护，避免超大输入导致 nonce 复用。

### Security
- 移除危险的 RSA PKCS#1 v1.5 加密路径，统一推荐 OAEP/PSS。
- 新增/改动的加密代码经过一次安全审查。

## [v1.1.10] - 2026-04

- 此前版本，详见 git 历史。
