package rsa

import (
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"encoding/base64"
)

// SignPSS 使用 RSA-PSS + SHA256 签名.
func SignPSS(plainText []byte, priFilePath string) ([]byte, error) {
	return SignPSSWithOptions(plainText, priFilePath, crypto.SHA256, nil)
}

// SignPSSBase64 使用 RSA-PSS + SHA256 签名并返回 Base64.
func SignPSSBase64(plainText []byte, priFilePath string) (string, error) {
	return SignPSSBase64WithOptions(plainText, priFilePath, crypto.SHA256, nil)
}

// VerifyPSS 使用 RSA-PSS + SHA256 验签.
func VerifyPSS(plainText []byte, pubFilePath string, signature []byte) error {
	return VerifyPSSWithOptions(plainText, pubFilePath, signature, crypto.SHA256, nil)
}

// VerifyPSSBase64 使用 RSA-PSS + SHA256 Base64 验签.
func VerifyPSSBase64(plainText []byte, pubFilePath, signature string) error {
	return VerifyPSSBase64WithOptions(plainText, pubFilePath, signature, crypto.SHA256, nil)
}

// SignPSSWithOptions 使用指定 hash 和 PSSOptions 签名.
func SignPSSWithOptions(plainText []byte, priFilePath string, hash crypto.Hash, opts *stdrsa.PSSOptions) ([]byte, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return nil, err
	}
	return SignPSSWithPrivateKey(privateKey, plainText, hash, opts)
}

// SignPSSBase64WithOptions 使用指定 hash 和 PSSOptions 签名并返回 Base64.
func SignPSSBase64WithOptions(plainText []byte, priFilePath string, hash crypto.Hash, opts *stdrsa.PSSOptions) (string, error) {
	signature, err := SignPSSWithOptions(plainText, priFilePath, hash, opts)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyPSSWithOptions 使用指定 hash 和 PSSOptions 验签.
func VerifyPSSWithOptions(plainText []byte, pubFilePath string, signature []byte, hash crypto.Hash, opts *stdrsa.PSSOptions) error {
	publicKey, err := ReadPublicKey(pubFilePath)
	if err != nil {
		return err
	}
	return VerifyPSSWithPublicKey(publicKey, plainText, signature, hash, opts)
}

// VerifyPSSBase64WithOptions 使用指定 hash 和 PSSOptions Base64 验签.
func VerifyPSSBase64WithOptions(plainText []byte, pubFilePath, signature string, hash crypto.Hash, opts *stdrsa.PSSOptions) error {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return VerifyPSSWithOptions(plainText, pubFilePath, raw, hash, opts)
}

// SignPSSWithPrivateKey 使用已解析私钥执行 RSA-PSS 签名.
func SignPSSWithPrivateKey(privateKey *stdrsa.PrivateKey, plainText []byte, hash crypto.Hash, opts *stdrsa.PSSOptions) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	digest, err := hashDigest(plainText, hash)
	if err != nil {
		return nil, err
	}
	return stdrsa.SignPSS(rand.Reader, privateKey, hash, digest, opts)
}

// VerifyPSSWithPublicKey 使用已解析公钥执行 RSA-PSS 验签.
func VerifyPSSWithPublicKey(publicKey *stdrsa.PublicKey, plainText, signature []byte, hash crypto.Hash, opts *stdrsa.PSSOptions) error {
	if publicKey == nil {
		return ErrInvalidPublicKey
	}
	digest, err := hashDigest(plainText, hash)
	if err != nil {
		return err
	}
	return stdrsa.VerifyPSS(publicKey, hash, digest, signature, opts)
}
