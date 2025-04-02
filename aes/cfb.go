package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type cfb struct {
	// key string //
	// iv  []byte
	aesImpl
}

// NewCFB returns a new AES.
func NewCFB(key string) AES {
	return &cfb{
		aesImpl: aesImpl{
			key: key,
			iv:  iv(),
		},
	}
}

// ErrDecryptFailed is returned when Decrypt is unable to decrypt due to
// invalid inputs.
var ErrDecryptFailed = errors.New("decrypt failed")

// Encrypt data. Uses AES-256-CFB encrypter.
func (c *cfb) Encrypt(data []byte) (string, error) {
	// keyb := sha256.Sum256([]byte(c.key))
	// ciph, err := aes.NewCipher(keyb[:])
	ciph, err := aes.NewCipher([]byte(c.key))

	if err != nil {
		return "", err
	}
	// The iv is added to the front of the final payload.
	encdata := make([]byte, aes.BlockSize*2+len(data))
	if _, err := rand.Read(encdata[:aes.BlockSize]); err != nil {
		return "", err
	}
	// The iv is also added to the front of the encrypted data so we can
	// verify after decrypting.
	dataiv := make([]byte, aes.BlockSize+len(data))
	copy(dataiv, encdata[:aes.BlockSize])
	copy(dataiv[aes.BlockSize:], data)
	cipher.NewCFBEncrypter(ciph, encdata[:aes.BlockSize]).
		XORKeyStream(encdata[aes.BlockSize:], dataiv)
	return base64.URLEncoding.EncodeToString(encdata), nil
}

// Decrypt data. Uses AES-256-CFB decrypter.
func (c *cfb) Decrypt(decryptStr string) (string, error) {
	// data should be at least aes.BlockSize + len(data)
	data, err := base64.URLEncoding.DecodeString(decryptStr)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", ErrDecryptFailed
	}
	// keyb := sha256.Sum256([]byte(c.key))
	// ciph, err := aes.NewCipher(keyb[:])
	ciph, err := aes.NewCipher([]byte(c.key))
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

func (c *cfb) i() {

}
