// Package encry 是一组 Go 加密/编码工具集合的根包，仅承载模块版本号。
//
// 实际能力分布在各子包中：
//   - 对称加密：aes（GCM/CBC/CFB）、chacha（XChaCha20-Poly1305）、stream（流式 AEAD）
//   - 非对称：rsa（OAEP/PSS）、ed（Ed25519）、ecdsa、ecdh、hpke、mlkem（后量子）
//   - 摘要/认证：sha256、hmac、md5、sha1
//   - 口令/派生：hash（argon2id、bcrypt）、hkdf
//   - 编码/工具：base64、sqids、sign
//
// 新系统优先选用现代默认能力（AES-GCM/ChaCha20-Poly1305、RSA-OAEP/PSS、Ed25519、SHA-256+）。
package encry
