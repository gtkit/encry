package rsa

import (
	"crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"encoding/base64"
	"errors"
)

var ErrOAEPMessageTooLong = errors.New("OAEP message is too long for the RSA key and hash")

// EncryptOAEP 使用 RSA-OAEP + SHA256 进行单块加密.
func EncryptOAEP(plainText []byte, pubFilePath string) ([]byte, error) {
	return EncryptOAEPWithOptions(plainText, pubFilePath, crypto.SHA256, nil)
}

// EncryptOAEPBase64 使用 RSA-OAEP + SHA256 进行单块加密并返回 Base64.
func EncryptOAEPBase64(plainText []byte, pubFilePath string) (string, error) {
	return EncryptOAEPBase64WithOptions(plainText, pubFilePath, crypto.SHA256, nil)
}

// DecryptOAEP 使用 RSA-OAEP + SHA256 进行单块解密.
func DecryptOAEP(cipherText []byte, priFilePath string) ([]byte, error) {
	return DecryptOAEPWithOptions(cipherText, priFilePath, crypto.SHA256, nil)
}

// DecryptOAEPBase64 使用 RSA-OAEP + SHA256 进行单块 Base64 解密.
func DecryptOAEPBase64(cipherText, priFilePath string) ([]byte, error) {
	return DecryptOAEPBase64WithOptions(cipherText, priFilePath, crypto.SHA256, nil)
}

// EncryptOAEPChunked 使用 RSA-OAEP + SHA256 进行分段加密.
func EncryptOAEPChunked(plainText []byte, pubFilePath string) ([]byte, error) {
	return EncryptOAEPChunkedWithOptions(plainText, pubFilePath, crypto.SHA256, nil)
}

// EncryptOAEPChunkedBase64 使用 RSA-OAEP + SHA256 进行分段加密并返回 Base64.
func EncryptOAEPChunkedBase64(plainText []byte, pubFilePath string) (string, error) {
	return EncryptOAEPChunkedBase64WithOptions(plainText, pubFilePath, crypto.SHA256, nil)
}

// DecryptOAEPChunked 使用 RSA-OAEP + SHA256 进行分段解密.
func DecryptOAEPChunked(cipherText []byte, priFilePath string) ([]byte, error) {
	return DecryptOAEPChunkedWithOptions(cipherText, priFilePath, crypto.SHA256, nil)
}

// DecryptOAEPChunkedBase64 使用 RSA-OAEP + SHA256 进行分段 Base64 解密.
func DecryptOAEPChunkedBase64(cipherText, priFilePath string) ([]byte, error) {
	return DecryptOAEPChunkedBase64WithOptions(cipherText, priFilePath, crypto.SHA256, nil)
}

// EncryptOAEPWithOptions 使用指定 hash 和 label 执行 RSA-OAEP 单块加密.
func EncryptOAEPWithOptions(plainText []byte, pubFilePath string, hash crypto.Hash, label []byte) ([]byte, error) {
	publicKey, err := ReadPublicKey(pubFilePath)
	if err != nil {
		return nil, err
	}
	return EncryptOAEPWithPublicKey(publicKey, plainText, hash, label)
}

// EncryptOAEPBase64WithOptions 使用指定 hash 和 label 执行 RSA-OAEP 单块加密并返回 Base64.
func EncryptOAEPBase64WithOptions(plainText []byte, pubFilePath string, hash crypto.Hash, label []byte) (string, error) {
	cipherText, err := EncryptOAEPWithOptions(plainText, pubFilePath, hash, label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptOAEPWithOptions 使用指定 hash 和 label 执行 RSA-OAEP 单块解密.
func DecryptOAEPWithOptions(cipherText []byte, priFilePath string, hash crypto.Hash, label []byte) ([]byte, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return nil, err
	}
	return DecryptOAEPWithPrivateKey(privateKey, cipherText, hash, label)
}

// DecryptOAEPBase64WithOptions 使用指定 hash 和 label 执行 RSA-OAEP 单块 Base64 解密.
func DecryptOAEPBase64WithOptions(cipherText, priFilePath string, hash crypto.Hash, label []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	return DecryptOAEPWithOptions(raw, priFilePath, hash, label)
}

// EncryptOAEPChunkedWithOptions 使用指定 hash 和 label 执行 RSA-OAEP 分段加密.
func EncryptOAEPChunkedWithOptions(plainText []byte, pubFilePath string, hash crypto.Hash, label []byte) ([]byte, error) {
	publicKey, err := ReadPublicKey(pubFilePath)
	if err != nil {
		return nil, err
	}
	return EncryptOAEPChunkedWithPublicKey(publicKey, plainText, hash, label)
}

// EncryptOAEPChunkedBase64WithOptions 使用指定 hash 和 label 执行 RSA-OAEP 分段加密并返回 Base64.
func EncryptOAEPChunkedBase64WithOptions(plainText []byte, pubFilePath string, hash crypto.Hash, label []byte) (string, error) {
	cipherText, err := EncryptOAEPChunkedWithOptions(plainText, pubFilePath, hash, label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptOAEPChunkedWithOptions 使用指定 hash 和 label 执行 RSA-OAEP 分段解密.
func DecryptOAEPChunkedWithOptions(cipherText []byte, priFilePath string, hash crypto.Hash, label []byte) ([]byte, error) {
	privateKey, err := ReadPrivateKey(priFilePath)
	if err != nil {
		return nil, err
	}
	return DecryptOAEPChunkedWithPrivateKey(privateKey, cipherText, hash, label)
}

// DecryptOAEPChunkedBase64WithOptions 使用指定 hash 和 label 执行 RSA-OAEP 分段 Base64 解密.
func DecryptOAEPChunkedBase64WithOptions(cipherText, priFilePath string, hash crypto.Hash, label []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	return DecryptOAEPChunkedWithOptions(raw, priFilePath, hash, label)
}

// EncryptOAEPWithPublicKey 使用已解析公钥执行 RSA-OAEP 单块加密.
func EncryptOAEPWithPublicKey(publicKey *stdrsa.PublicKey, plainText []byte, hash crypto.Hash, label []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}
	if !hash.Available() {
		return nil, ErrUnsupportedHash
	}
	if len(plainText) > maxOAEPPlaintextSize(publicKey, hash) {
		return nil, ErrOAEPMessageTooLong
	}
	return stdrsa.EncryptOAEP(hash.New(), rand.Reader, publicKey, plainText, label)
}

// DecryptOAEPWithPrivateKey 使用已解析私钥执行 RSA-OAEP 单块解密.
func DecryptOAEPWithPrivateKey(privateKey *stdrsa.PrivateKey, cipherText []byte, hash crypto.Hash, label []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if !hash.Available() {
		return nil, ErrUnsupportedHash
	}
	if len(cipherText) == 0 {
		return []byte{}, nil
	}
	if len(cipherText) != privateKey.Size() {
		return nil, errInvalidCiphertextSize(len(cipherText), privateKey.Size())
	}
	return stdrsa.DecryptOAEP(hash.New(), rand.Reader, privateKey, cipherText, label)
}

// EncryptOAEPChunkedWithPublicKey 使用已解析公钥执行 RSA-OAEP 分段加密.
func EncryptOAEPChunkedWithPublicKey(publicKey *stdrsa.PublicKey, plainText []byte, hash crypto.Hash, label []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}
	if !hash.Available() {
		return nil, ErrUnsupportedHash
	}
	if len(plainText) == 0 {
		return []byte{}, nil
	}

	blockSize := maxOAEPPlaintextSize(publicKey, hash)
	if blockSize <= 0 {
		return nil, ErrOAEPMessageTooLong
	}

	var encrypted []byte
	for offset := 0; offset < len(plainText); offset += blockSize {
		end := min(offset+blockSize, len(plainText))
		chunk, err := stdrsa.EncryptOAEP(hash.New(), rand.Reader, publicKey, plainText[offset:end], label)
		if err != nil {
			return nil, err
		}
		encrypted = append(encrypted, chunk...)
	}
	return encrypted, nil
}

// DecryptOAEPChunkedWithPrivateKey 使用已解析私钥执行 RSA-OAEP 分段解密.
func DecryptOAEPChunkedWithPrivateKey(privateKey *stdrsa.PrivateKey, cipherText []byte, hash crypto.Hash, label []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if !hash.Available() {
		return nil, ErrUnsupportedHash
	}
	if len(cipherText) == 0 {
		return []byte{}, nil
	}

	keySize := privateKey.Size()
	if len(cipherText)%keySize != 0 {
		return nil, errInvalidCiphertextSize(len(cipherText), keySize)
	}

	var plainText []byte
	for offset := 0; offset < len(cipherText); offset += keySize {
		chunk, err := stdrsa.DecryptOAEP(hash.New(), rand.Reader, privateKey, cipherText[offset:offset+keySize], label)
		if err != nil {
			return nil, err
		}
		plainText = append(plainText, chunk...)
	}
	return plainText, nil
}

func maxOAEPPlaintextSize(publicKey *stdrsa.PublicKey, hash crypto.Hash) int {
	return publicKey.Size() - 2*hash.Size() - 2
}
