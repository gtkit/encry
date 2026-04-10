package rsa

import (
	"crypto"
	"crypto/md5" // #nosec G501 -- legacy compatibility for PKCS#1 v1.5 signing helpers.
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha1" // #nosec G505 -- legacy compatibility for PKCS#1 v1.5 signing helpers.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

// Deprecated: Sign uses RSA PKCS#1 v1.5 signing and is kept only for legacy
// compatibility. New systems should use SignPSS or SignPSSBase64.
func Sign(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.SHA512)
}

// Deprecated: Verify uses RSA PKCS#1 v1.5 verification and is kept only for
// legacy compatibility. New systems should use VerifyPSS or VerifyPSSBase64.
func Verify(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.SHA512)
}

// Deprecated: SignWithHash uses RSA PKCS#1 v1.5 signing and is kept only for
// legacy compatibility. New systems should use SignPSSWithOptions.
func SignWithHash(plainText []byte, priFilePath string, hash crypto.Hash) ([]byte, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return nil, err
	}
	return SignPKCS1v15(privateKey, plainText, hash)
}

// Deprecated: SignBase64WithHash uses RSA PKCS#1 v1.5 signing and is kept only
// for legacy compatibility. New systems should use SignPSSBase64WithOptions.
func SignBase64WithHash(plainText []byte, priFilePath string, hash crypto.Hash) (string, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return "", err
	}
	return SignPKCS1v15Base64(privateKey, plainText, hash)
}

// Deprecated: VerifyWithHash uses RSA PKCS#1 v1.5 verification and is kept
// only for legacy compatibility. New systems should use VerifyPSSWithOptions.
func VerifyWithHash(plainText []byte, pubFilePath string, signText []byte, hash crypto.Hash) error {
	publicKey, err := ReadPublicKey(pubFilePath)
	if err != nil {
		return err
	}
	return VerifyPKCS1v15(publicKey, plainText, signText, hash)
}

// Deprecated: VerifyBase64WithHash uses RSA PKCS#1 v1.5 verification and is
// kept only for legacy compatibility. New systems should use
// VerifyPSSBase64WithOptions.
func VerifyBase64WithHash(plainText []byte, pubFilePath, signText string, hash crypto.Hash) error {
	publicKey, err := ReadPublicKey(pubFilePath)
	if err != nil {
		return err
	}
	return VerifyPKCS1v15Base64(publicKey, plainText, signText, hash)
}

// SignPKCS1v15 使用已解析私钥执行 PKCS#1 v1.5 签名.
func SignPKCS1v15(privateKey *stdrsa.PrivateKey, plainText []byte, hash crypto.Hash) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	digest, err := hashDigest(plainText, hash)
	if err != nil {
		return nil, err
	}
	return stdrsa.SignPKCS1v15(rand.Reader, privateKey, hash, digest)
}

// SignPKCS1v15Base64 使用已解析私钥执行 PKCS#1 v1.5 签名并编码为 Base64.
func SignPKCS1v15Base64(privateKey *stdrsa.PrivateKey, plainText []byte, hash crypto.Hash) (string, error) {
	signature, err := SignPKCS1v15(privateKey, plainText, hash)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyPKCS1v15 使用已解析公钥执行 PKCS#1 v1.5 验签.
func VerifyPKCS1v15(publicKey *stdrsa.PublicKey, plainText, signText []byte, hash crypto.Hash) error {
	if publicKey == nil {
		return ErrInvalidPublicKey
	}
	digest, err := hashDigest(plainText, hash)
	if err != nil {
		return err
	}
	return stdrsa.VerifyPKCS1v15(publicKey, hash, digest, signText)
}

// VerifyPKCS1v15Base64 使用已解析公钥执行 PKCS#1 v1.5 Base64 验签.
func VerifyPKCS1v15Base64(publicKey *stdrsa.PublicKey, plainText []byte, signText string, hash crypto.Hash) error {
	signature, err := base64.StdEncoding.DecodeString(signText)
	if err != nil {
		return err
	}
	return VerifyPKCS1v15(publicKey, plainText, signature, hash)
}

// Deprecated: SignSHA256 uses RSA PKCS#1 v1.5 signing and is kept only for
// legacy compatibility. New systems should use SignPSSWithOptions.
func SignSHA256(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.SHA256)
}

// Deprecated: SignSHA256Base64 uses RSA PKCS#1 v1.5 signing and is kept only
// for legacy compatibility. New systems should use SignPSSBase64WithOptions.
func SignSHA256Base64(plainText []byte, priFilePath string) (string, error) {
	return SignBase64WithHash(plainText, priFilePath, crypto.SHA256)
}

// Deprecated: VerifySHA256 uses RSA PKCS#1 v1.5 verification and is kept only
// for legacy compatibility. New systems should use VerifyPSSWithOptions.
func VerifySHA256(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.SHA256)
}

// Deprecated: VerifySHA256Base64 uses RSA PKCS#1 v1.5 verification and is kept
// only for legacy compatibility. New systems should use
// VerifyPSSBase64WithOptions.
func VerifySHA256Base64(plainText []byte, pubFilePath, signText string) error {
	return VerifyBase64WithHash(plainText, pubFilePath, signText, crypto.SHA256)
}

// Deprecated: SignSHA512Base64 uses RSA PKCS#1 v1.5 signing and is kept only
// for legacy compatibility. New systems should use SignPSSBase64WithOptions.
func SignSHA512Base64(plainText []byte, priFilePath string) (string, error) {
	return SignBase64WithHash(plainText, priFilePath, crypto.SHA512)
}

// Deprecated: VerifySHA512Base64 uses RSA PKCS#1 v1.5 verification and is kept
// only for legacy compatibility. New systems should use
// VerifyPSSBase64WithOptions.
func VerifySHA512Base64(plainText []byte, pubFilePath, signText string) error {
	return VerifyBase64WithHash(plainText, pubFilePath, signText, crypto.SHA512)
}

// Deprecated: SignSHA1 uses RSA PKCS#1 v1.5 + SHA1 signing and is kept only
// for legacy compatibility.
func SignSHA1(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.SHA1)
}

// Deprecated: VerifySHA1 uses RSA PKCS#1 v1.5 + SHA1 verification and is kept
// only for legacy compatibility.
func VerifySHA1(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.SHA1)
}

// Deprecated: SignMD5 uses RSA PKCS#1 v1.5 + MD5 signing and is kept only for
// legacy compatibility.
func SignMD5(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.MD5)
}

// Deprecated: SignMD5Base64 uses RSA PKCS#1 v1.5 + MD5 signing and is kept
// only for legacy compatibility.
func SignMD5Base64(plainText []byte, priFilePath string) (string, error) {
	return SignBase64WithHash(plainText, priFilePath, crypto.MD5)
}

// Deprecated: VerifyMD5Bytes uses RSA PKCS#1 v1.5 + MD5 verification and is
// kept only for legacy compatibility.
func VerifyMD5Bytes(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.MD5)
}

// Deprecated: VerifyMD5 uses RSA PKCS#1 v1.5 + MD5 verification and is kept
// only for legacy compatibility.
func VerifyMD5(plainText, sign, pubFilePath string) error {
	return VerifyBase64WithHash([]byte(plainText), pubFilePath, sign, crypto.MD5)
}

// Deprecated: SignCS8MD5 uses RSA PKCS#1 v1.5 + MD5 signing and is kept only
// for legacy compatibility.
func SignCS8MD5(plainText, priFilePath string) (string, error) {
	block, err := readPEMFile(priFilePath)
	if err != nil {
		return "", err
	}
	privateKey, err := parsePKCS8PrivateKey(block.Bytes, priFilePath)
	if err != nil {
		return "", err
	}
	return SignPKCS1v15Base64(privateKey, []byte(plainText), crypto.MD5)
}

func hashDigest(plainText []byte, hash crypto.Hash) ([]byte, error) {
	//nolint:exhaustive // unsupported hash values fall through to the default error.
	switch hash {
	case crypto.MD5:
		sum := md5.Sum(plainText) // #nosec G401 -- legacy compatibility for PKCS#1 v1.5 signing helpers.
		return sum[:], nil
	case crypto.SHA1:
		sum := sha1.Sum(plainText) // #nosec G401 -- legacy compatibility for PKCS#1 v1.5 signing helpers.
		return sum[:], nil
	case crypto.SHA224:
		sum := sha256.Sum224(plainText)
		return sum[:], nil
	case crypto.SHA256:
		sum := sha256.Sum256(plainText)
		return sum[:], nil
	case crypto.SHA384:
		sum := sha512.Sum384(plainText)
		return sum[:], nil
	case crypto.SHA512:
		sum := sha512.Sum512(plainText)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedHash, hash)
	}
}
