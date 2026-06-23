package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type cfb struct {
	// key string //
	// iv  []byte
	aesImpl
}

// NewCFB 创建一个 AES-CFB 实例。
//
// Deprecated: CFB 模式未认证（且已被 Go 标准库弃用）。新系统请使用 NewGCM，
// 或 chacha / stream 包；CFB 仅为兼容旧密文保留。
func NewCFB(key string) AES {
	return &cfb{
		aesImpl: newAESImpl(key),
	}
}

// ErrDecryptFailed is returned when Decrypt is unable to decrypt due to
// invalid inputs.
var ErrDecryptFailed = errors.New("decrypt failed")

// Encrypt data. Uses AES-256-CFB encrypter.
func (c *cfb) Encrypt(data []byte) (string, error) {
	ciph, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	encdata := make([]byte, 1+aes.BlockSize+len(data))
	encdata[0] = cipherFormatVersion
	iv := encdata[1 : 1+aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// #nosec G407 -- iv is filled from crypto/rand above before use.
	stream := cipher.NewCFBEncrypter(ciph, iv) //nolint:staticcheck // CFB 仅为兼容旧密文保留，新系统请用 GCM
	stream.XORKeyStream(encdata[1+aes.BlockSize:], data)
	return base64.URLEncoding.EncodeToString(encdata), nil
}

// Decrypt data. Uses AES-256-CFB decrypter.
func (c *cfb) Decrypt(decryptStr string) (string, error) {
	// data should be at least aes.BlockSize + len(data)
	data, err := base64.URLEncoding.DecodeString(decryptStr)
	if err != nil {
		return "", err
	}

	if len(data) > 0 && data[0] == cipherFormatVersion {
		plainText, err := decryptCurrentCFB(c.key, data)
		if err == nil {
			return plainText, nil
		}
	}

	return decryptLegacyCFB(c.key, data)
}

func decryptCurrentCFB(key, data []byte) (string, error) {
	if len(data) < 1+aes.BlockSize {
		return "", ErrDecryptFailed
	}

	ciph, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plainText := make([]byte, len(data)-1-aes.BlockSize)
	stream := cipher.NewCFBDecrypter(ciph, data[1:1+aes.BlockSize]) //nolint:staticcheck // CFB 仅为兼容旧密文保留，新系统请用 GCM
	stream.XORKeyStream(plainText, data[1+aes.BlockSize:])
	return string(plainText), nil
}

func decryptLegacyCFB(key, data []byte) (string, error) {
	if len(data) < aes.BlockSize {
		return "", ErrDecryptFailed
	}

	ciph, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decdata := make([]byte, len(data)-aes.BlockSize)
	stream := cipher.NewCFBDecrypter(ciph, data[:aes.BlockSize]) //nolint:staticcheck // CFB 仅为兼容旧密文保留，新系统请用 GCM
	stream.XORKeyStream(decdata, data[aes.BlockSize:])
	if len(decdata) < aes.BlockSize {
		return "", ErrDecryptFailed
	}
	if !bytes.Equal(data[:aes.BlockSize], decdata[:aes.BlockSize]) {
		return "", ErrDecryptFailed
	}
	return string(decdata[aes.BlockSize:]), nil
}
