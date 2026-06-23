package rsa

import (
	"fmt"
	"path/filepath"
)

// GenerateRsaKey 生成 PKCS#1 PEM 格式 RSA 密钥对文件（私钥 0600，公钥 0644）.
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

// errInvalidCiphertextSize 供 OAEP 解密做长度校验时构造错误.
func errInvalidCiphertextSize(size, keySize int) error {
	return fmt.Errorf("invalid ciphertext size %d for key size %d", size, keySize)
}
