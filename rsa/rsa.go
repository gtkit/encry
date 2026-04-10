package rsa

import (
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrInvalidPEMBlock   = errors.New("invalid PEM block")
	ErrInvalidPrivateKey = errors.New("invalid RSA private key")
	ErrInvalidPublicKey  = errors.New("invalid RSA public key")
	ErrUnsupportedHash   = errors.New("unsupported hash algorithm")
)

// GetKey 读取公钥/私钥文件，获取解码的 pem block.
func GetKey(filePath string) (*pem.Block, error) {
	return readPEMFile(filePath)
}

// Error 保留旧的错误格式化接口，避免破坏兼容性.
func Error(file string, line int, err string) error {
	return fmt.Errorf("file:%s line:%d error:%s", file, line, err)
}

// GenerateKeyPair 生成 RSA 密钥对.
func GenerateKeyPair(keySize int) (*stdrsa.PrivateKey, *stdrsa.PublicKey, error) {
	privateKey, err := stdrsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// GeneratePKCS1KeyPEM 生成 PKCS#1 PEM 格式密钥对.
func GeneratePKCS1KeyPEM(keySize int) ([]byte, []byte, error) {
	privateKey, publicKey, err := GenerateKeyPair(keySize)
	if err != nil {
		return nil, nil, err
	}
	return MarshalPKCS1PrivateKeyPEM(privateKey), MarshalPKCS1PublicKeyPEM(publicKey), nil
}

// ReadPrivateKey 从 PEM 文件中读取 RSA 私钥，兼容 PKCS#1 与 PKCS#8.
func ReadPrivateKey(filePath string) (*stdrsa.PrivateKey, error) {
	block, err := readPEMFile(filePath)
	if err != nil {
		return nil, err
	}
	return parsePrivateKeyBlock(block, filePath)
}

// ReadPublicKey 从 PEM 文件中读取 RSA 公钥，兼容 PKCS#1 与 PKIX.
func ReadPublicKey(filePath string) (*stdrsa.PublicKey, error) {
	block, err := readPEMFile(filePath)
	if err != nil {
		return nil, err
	}
	return parsePublicKeyBlock(block, filePath)
}

// ParsePrivateKeyPEM 从 PEM 内容中解析 RSA 私钥，兼容 PKCS#1 与 PKCS#8.
func ParsePrivateKeyPEM(data []byte) (*stdrsa.PrivateKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}
	return parsePrivateKeyBlock(block, "inline PEM")
}

// ParsePublicKeyPEM 从 PEM 内容中解析 RSA 公钥，兼容 PKCS#1 与 PKIX.
func ParsePublicKeyPEM(data []byte) (*stdrsa.PublicKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}
	return parsePublicKeyBlock(block, "inline PEM")
}

// MarshalPKCS1PrivateKeyPEM 将私钥编码为 PKCS#1 PEM.
func MarshalPKCS1PrivateKeyPEM(privateKey *stdrsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

// MarshalPKCS1PublicKeyPEM 将公钥编码为 PKCS#1 PEM.
func MarshalPKCS1PublicKeyPEM(publicKey *stdrsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})
}

// MarshalPKIXPublicKeyPEM 将公钥编码为 PKIX PEM.
func MarshalPKIXPublicKeyPEM(publicKey *stdrsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func readPEMFile(filePath string) (*pem.Block, error) {
	buf, err := os.ReadFile(filePath) // #nosec G304 -- this helper intentionally reads a caller-provided key path.
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", filePath, err)
	}
	block, err := decodePEMBlock(buf)
	if err != nil {
		return nil, fmt.Errorf("decode PEM %s: %w", filePath, err)
	}
	return block, nil
}

func decodePEMBlock(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEMBlock
	}
	return block, nil
}

func parsePrivateKeyBlock(block *pem.Block, source string) (*stdrsa.PrivateKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		if key, err := parsePKCS1PrivateKey(block.Bytes, source); err == nil {
			return key, nil
		}
		if key, err := parsePKCS8PrivateKey(block.Bytes, source); err == nil {
			return key, nil
		}
	case "PRIVATE KEY":
		if key, err := parsePKCS1PrivateKey(block.Bytes, source); err == nil {
			return key, nil
		}
		if key, err := parsePKCS8PrivateKey(block.Bytes, source); err == nil {
			return key, nil
		}
	default:
		if key, err := parsePKCS1PrivateKey(block.Bytes, source); err == nil {
			return key, nil
		}
		if key, err := parsePKCS8PrivateKey(block.Bytes, source); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrInvalidPrivateKey, source)
}

func parsePublicKeyBlock(block *pem.Block, source string) (*stdrsa.PublicKey, error) {
	switch block.Type {
	case "RSA PUBLIC KEY":
		if key, err := parsePKCS1PublicKey(block.Bytes, source); err == nil {
			return key, nil
		}
		if key, err := parsePKIXPublicKey(block.Bytes, source); err == nil {
			return key, nil
		}
	case "PUBLIC KEY":
		if key, err := parsePKIXPublicKey(block.Bytes, source); err == nil {
			return key, nil
		}
		if key, err := parsePKCS1PublicKey(block.Bytes, source); err == nil {
			return key, nil
		}
	default:
		if key, err := parsePKIXPublicKey(block.Bytes, source); err == nil {
			return key, nil
		}
		if key, err := parsePKCS1PublicKey(block.Bytes, source); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrInvalidPublicKey, source)
}

func parsePKIXPublicKey(der []byte, source string) (*stdrsa.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key %s: %w", source, err)
	}
	key, ok := publicKey.(*stdrsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPublicKey, source)
	}
	return key, nil
}

func parsePKCS1PublicKey(der []byte, source string) (*stdrsa.PublicKey, error) {
	publicKey, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#1 public key %s: %w", source, err)
	}
	return publicKey, nil
}

func parsePKCS1PrivateKey(der []byte, source string) (*stdrsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#1 private key %s: %w", source, err)
	}
	return privateKey, nil
}

func parsePKCS8PrivateKey(der []byte, source string) (*stdrsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key %s: %w", source, err)
	}
	key, ok := privateKey.(*stdrsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPrivateKey, source)
	}
	return key, nil
}

func writePEMFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}
