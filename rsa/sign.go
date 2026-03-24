package rsa

import (
	"crypto"
	"crypto/md5" //nolint:gosec //legacy compatibility
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/sha1" //nolint:gosec //legacy compatibility
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
)

// Sign 使用 PKCS#1 v1.5 + SHA512 签名，保留兼容旧接口.
func Sign(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.SHA512)
}

// Verify 使用 PKCS#1 v1.5 + SHA512 验签，保留兼容旧接口.
func Verify(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.SHA512)
}

// SignWithHash 使用指定 hash 执行 PKCS#1 v1.5 签名.
func SignWithHash(plainText []byte, priFilePath string, hash crypto.Hash) ([]byte, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return nil, err
	}
	return SignPKCS1v15(privateKey, plainText, hash)
}

// SignBase64WithHash 使用指定 hash 执行 PKCS#1 v1.5 签名并编码为 Base64.
func SignBase64WithHash(plainText []byte, priFilePath string, hash crypto.Hash) (string, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return "", err
	}
	return SignPKCS1v15Base64(privateKey, plainText, hash)
}

// VerifyWithHash 使用指定 hash 执行 PKCS#1 v1.5 验签.
func VerifyWithHash(plainText []byte, pubFilePath string, signText []byte, hash crypto.Hash) error {
	publicKey, err := ReadPublicKey(pubFilePath)
	if err != nil {
		return err
	}
	return VerifyPKCS1v15(publicKey, plainText, signText, hash)
}

// VerifyBase64WithHash 使用指定 hash 执行 PKCS#1 v1.5 Base64 验签.
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

// SignSHA256 使用 PKCS#1 v1.5 + SHA256 签名.
func SignSHA256(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.SHA256)
}

// SignSHA256Base64 使用 PKCS#1 v1.5 + SHA256 签名并返回 Base64.
func SignSHA256Base64(plainText []byte, priFilePath string) (string, error) {
	return SignBase64WithHash(plainText, priFilePath, crypto.SHA256)
}

// VerifySHA256 使用 PKCS#1 v1.5 + SHA256 验签.
func VerifySHA256(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.SHA256)
}

// VerifySHA256Base64 使用 PKCS#1 v1.5 + SHA256 Base64 验签.
func VerifySHA256Base64(plainText []byte, pubFilePath, signText string) error {
	return VerifyBase64WithHash(plainText, pubFilePath, signText, crypto.SHA256)
}

// SignSHA512Base64 使用 PKCS#1 v1.5 + SHA512 签名并返回 Base64.
func SignSHA512Base64(plainText []byte, priFilePath string) (string, error) {
	return SignBase64WithHash(plainText, priFilePath, crypto.SHA512)
}

// VerifySHA512Base64 使用 PKCS#1 v1.5 + SHA512 Base64 验签.
func VerifySHA512Base64(plainText []byte, pubFilePath, signText string) error {
	return VerifyBase64WithHash(plainText, pubFilePath, signText, crypto.SHA512)
}

// SignSHA1 使用 PKCS#1 v1.5 + SHA1 签名，兼容旧协议使用场景.
func SignSHA1(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.SHA1)
}

// VerifySHA1 使用 PKCS#1 v1.5 + SHA1 验签，兼容旧协议使用场景.
func VerifySHA1(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.SHA1)
}

// SignMD5 使用 PKCS#1 v1.5 + MD5 签名，兼容旧协议使用场景.
func SignMD5(plainText []byte, priFilePath string) ([]byte, error) {
	return SignWithHash(plainText, priFilePath, crypto.MD5)
}

// SignMD5Base64 使用 PKCS#1 v1.5 + MD5 签名并返回 Base64.
func SignMD5Base64(plainText []byte, priFilePath string) (string, error) {
	return SignBase64WithHash(plainText, priFilePath, crypto.MD5)
}

// VerifyMD5Bytes 使用 PKCS#1 v1.5 + MD5 验签，兼容旧协议使用场景.
func VerifyMD5Bytes(plainText []byte, pubFilePath string, signText []byte) error {
	return VerifyWithHash(plainText, pubFilePath, signText, crypto.MD5)
}

// VerifyMD5 验证 Base64 编码的 PKCS#1 v1.5 + MD5 签名.
func VerifyMD5(plainText, sign, pubFilePath string) error {
	return VerifyBase64WithHash([]byte(plainText), pubFilePath, sign, crypto.MD5)
}

// SignCS8MD5 保留兼容旧接口: 使用 PKCS#8 私钥执行 PKCS#1 v1.5 + MD5 Base64 签名.
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
	switch hash {
	case crypto.MD5:
		sum := md5.Sum(plainText) //nolint:gosec //legacy compatibility
		return sum[:], nil
	case crypto.SHA1:
		sum := sha1.Sum(plainText) //nolint:gosec //legacy compatibility
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
		return nil, ErrUnsupportedHash
	}
}
