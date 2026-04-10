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

// NewCFB returns a new AES.
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
	cipher.NewCFBEncrypter(ciph, iv).
		XORKeyStream(encdata[1+aes.BlockSize:], data)
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
	cipher.NewCFBDecrypter(ciph, data[1:1+aes.BlockSize]).
		XORKeyStream(plainText, data[1+aes.BlockSize:])
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
	cipher.NewCFBDecrypter(ciph, data[:aes.BlockSize]).
		XORKeyStream(decdata, data[aes.BlockSize:])
	if len(decdata) < aes.BlockSize {
		return "", ErrDecryptFailed
	}
	if !bytes.Equal(data[:aes.BlockSize], decdata[:aes.BlockSize]) {
		return "", ErrDecryptFailed
	}
	return string(decdata[aes.BlockSize:]), nil
}
