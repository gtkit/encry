package rsa

import (
	"bytes"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
)

const PKCS1PaddingLength = 11

var (
	ErrCipherTextTooLong = errors.New("ciphertext is larger than one RSA block")
)

// GenerateRsaKey 生成 PKCS#1 PEM 格式 RSA 密钥对文件.
func GenerateRsaKey(keySize int, dirPath string) error {
	privatePEM, publicPEM, err := GeneratePKCS1KeyPEM(keySize)
	if err != nil {
		return err
	}

	if err := writePEMFile(filepath.Join(dirPath, "private.pem"), privatePEM, 0o600); err != nil {
		return err
	}
	return writePEMFile(filepath.Join(dirPath, "public.pem"), publicPEM, 0o644)
}

// Deprecated: Encrypt uses RSA PKCS#1 v1.5 encryption and is kept only for
// legacy compatibility. New systems should use EncryptOAEP or
// EncryptOAEPBase64.
func Encrypt(plainText []byte, filePath string) ([]byte, error) {
	publicKey, err := ReadPublicKey(filePath)
	if err != nil {
		return nil, err
	}
	return EncryptPKCS1v15(publicKey, plainText)
}

// Deprecated: EncryptToBase64 uses RSA PKCS#1 v1.5 encryption and is kept only
// for legacy compatibility. New systems should use EncryptOAEPBase64.
func EncryptToBase64(plainText []byte, filePath string) (string, error) {
	publicKey, err := ReadPublicKey(filePath)
	if err != nil {
		return "", err
	}
	return EncryptPKCS1v15Base64(publicKey, plainText)
}

// Deprecated: Decrypt uses RSA PKCS#1 v1.5 decryption and is kept only for
// legacy compatibility. New systems should use DecryptOAEP or
// DecryptOAEPBase64.
func Decrypt(cipherText []byte, filePath string) ([]byte, error) {
	privateKey, err := ReadPrivateKey(filePath)
	if err != nil {
		return nil, err
	}
	return DecryptPKCS1v15(privateKey, cipherText)
}

// Deprecated: DecryptBase64 uses RSA PKCS#1 v1.5 decryption and is kept only
// for legacy compatibility. New systems should use DecryptOAEPBase64.
func DecryptBase64(cipherText, filePath string) ([]byte, error) {
	privateKey, err := ReadPrivateKey(filePath)
	if err != nil {
		return nil, err
	}
	return DecryptPKCS1v15Base64(privateKey, cipherText)
}

// Deprecated: EncryptBlock uses chunked RSA PKCS#1 v1.5 encryption and is kept
// only for legacy compatibility. New systems should use
// EncryptOAEPChunkedBase64.
func EncryptBlock(src []byte, filePath string) (string, error) {
	publicKey, err := ReadPublicKey(filePath)
	if err != nil {
		return "", err
	}
	return EncryptPKCS1v15ChunkedBase64(publicKey, src)
}

// Deprecated: EncryptBlockBytes uses chunked RSA PKCS#1 v1.5 encryption and is
// kept only for legacy compatibility. New systems should use
// EncryptOAEPChunked.
func EncryptBlockBytes(src []byte, filePath string) ([]byte, error) {
	publicKey, err := ReadPublicKey(filePath)
	if err != nil {
		return nil, err
	}
	return EncryptPKCS1v15Chunked(publicKey, src)
}

// Deprecated: DecryptBlock uses chunked RSA PKCS#1 v1.5 decryption and is kept
// only for legacy compatibility. New systems should use DecryptOAEPChunked.
func DecryptBlock(src []byte, filePath string) ([]byte, error) {
	privateKey, err := ReadPrivateKey(filePath)
	if err != nil {
		return nil, err
	}
	return DecryptPKCS1v15Chunked(privateKey, src)
}

// Deprecated: DecryptBlockBase64 uses chunked RSA PKCS#1 v1.5 decryption and
// is kept only for legacy compatibility. New systems should use
// DecryptOAEPChunkedBase64.
func DecryptBlockBase64(src, filePath string) ([]byte, error) {
	privateKey, err := ReadPrivateKey(filePath)
	if err != nil {
		return nil, err
	}
	return DecryptPKCS1v15ChunkedBase64(privateKey, src)
}

// EncryptPKCS1v15 使用 RSA 公钥执行单块 PKCS#1 v1.5 加密.
func EncryptPKCS1v15(publicKey *stdrsa.PublicKey, plainText []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}
	if len(plainText) > maxPKCS1v15PlaintextSize(publicKey) {
		return nil, stdrsa.ErrMessageTooLong
	}
	return stdrsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
}

// EncryptPKCS1v15Base64 使用 RSA 公钥执行单块 PKCS#1 v1.5 加密并编码为 Base64.
func EncryptPKCS1v15Base64(publicKey *stdrsa.PublicKey, plainText []byte) (string, error) {
	cipherText, err := EncryptPKCS1v15(publicKey, plainText)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptPKCS1v15 使用 RSA 私钥执行单块 PKCS#1 v1.5 解密.
func DecryptPKCS1v15(privateKey *stdrsa.PrivateKey, cipherText []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(cipherText) == 0 {
		return []byte{}, nil
	}
	if len(cipherText) != privateKey.Size() {
		if len(cipherText) > privateKey.Size() {
			return nil, ErrCipherTextTooLong
		}
		return nil, errInvalidCiphertextSize(len(cipherText), privateKey.Size())
	}
	return stdrsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
}

// DecryptPKCS1v15Base64 使用 RSA 私钥执行单块 PKCS#1 v1.5 Base64 解密.
func DecryptPKCS1v15Base64(privateKey *stdrsa.PrivateKey, cipherText string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	return DecryptPKCS1v15(privateKey, raw)
}

// EncryptPKCS1v15Chunked 使用 RSA 公钥执行分段 PKCS#1 v1.5 加密.
func EncryptPKCS1v15Chunked(publicKey *stdrsa.PublicKey, plainText []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}
	if len(plainText) == 0 {
		return []byte{}, nil
	}

	blockSize := maxPKCS1v15PlaintextSize(publicKey)
	var buffer bytes.Buffer
	for offset := 0; offset < len(plainText); offset += blockSize {
		end := min(offset+blockSize, len(plainText))
		chunk, err := stdrsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText[offset:end])
		if err != nil {
			return nil, err
		}
		buffer.Write(chunk)
	}
	return buffer.Bytes(), nil
}

// EncryptPKCS1v15ChunkedBase64 使用 RSA 公钥执行分段 PKCS#1 v1.5 加密并编码为 Base64.
func EncryptPKCS1v15ChunkedBase64(publicKey *stdrsa.PublicKey, plainText []byte) (string, error) {
	cipherText, err := EncryptPKCS1v15Chunked(publicKey, plainText)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptPKCS1v15Chunked 使用 RSA 私钥执行分段 PKCS#1 v1.5 解密.
func DecryptPKCS1v15Chunked(privateKey *stdrsa.PrivateKey, cipherText []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(cipherText) == 0 {
		return []byte{}, nil
	}

	keySize := privateKey.Size()
	if len(cipherText)%keySize != 0 {
		return nil, errInvalidCiphertextSize(len(cipherText), keySize)
	}

	var buffer bytes.Buffer
	for offset := 0; offset < len(cipherText); offset += keySize {
		chunk, err := stdrsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText[offset:offset+keySize])
		if err != nil {
			return nil, err
		}
		buffer.Write(chunk)
	}
	return buffer.Bytes(), nil
}

// DecryptPKCS1v15ChunkedBase64 使用 RSA 私钥执行分段 PKCS#1 v1.5 Base64 解密.
func DecryptPKCS1v15ChunkedBase64(privateKey *stdrsa.PrivateKey, cipherText string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	return DecryptPKCS1v15Chunked(privateKey, raw)
}

func maxPKCS1v15PlaintextSize(publicKey *stdrsa.PublicKey) int {
	return publicKey.Size() - PKCS1PaddingLength
}

func errInvalidCiphertextSize(size, keySize int) error {
	return fmt.Errorf("invalid ciphertext size %d for key size %d", size, keySize)
}
