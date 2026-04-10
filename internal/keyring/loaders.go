package keyring

import (
	"crypto/ed25519"
	stdrsa "crypto/rsa"
	"os"
	"path/filepath"
	"strings"

	"github.com/gtkit/encry/ed"
	encryrsa "github.com/gtkit/encry/rsa"
)

// Ed25519KeyPair 表示一个可用于签名验签的 Ed25519 密钥对.
type Ed25519KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// RSAKeyPair 表示一个可用于签名验签或解密的 RSA 密钥对.
type RSAKeyPair struct {
	Private *stdrsa.PrivateKey
	Public  *stdrsa.PublicKey
}

// LoadStringKeys 加载形如 <kid><suffix> 的字符串密钥文件.
func LoadStringKeys(dir, suffix string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		kid := strings.TrimSuffix(entry.Name(), suffix)
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name())) // #nosec G304 -- file name comes from os.ReadDir enumeration under the supplied directory.
		if err != nil {
			return nil, err
		}
		keys[kid] = strings.TrimSpace(string(raw))
	}
	return keys, nil
}

// LoadEd25519KeyPairs 从 <dir>/<kid>/{private,public}.pem 加载 Ed25519 密钥对.
func LoadEd25519KeyPairs(dir string) (map[string]Ed25519KeyPair, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]Ed25519KeyPair, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		kid := entry.Name()
		privateKey, err := ed.ReadPrivateKey(filepath.Join(dir, kid, "private.pem"))
		if err != nil {
			return nil, err
		}
		publicKey, err := ed.ReadPublicKey(filepath.Join(dir, kid, "public.pem"))
		if err != nil {
			return nil, err
		}
		keys[kid] = Ed25519KeyPair{
			Private: privateKey,
			Public:  publicKey,
		}
	}
	return keys, nil
}

// LoadRSAKeyPairs 从 <dir>/<kid>/{private,public}.pem 加载 RSA 密钥对.
func LoadRSAKeyPairs(dir string) (map[string]RSAKeyPair, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]RSAKeyPair, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		kid := entry.Name()
		privateKey, err := encryrsa.ReadPrivateKey(filepath.Join(dir, kid, "private.pem"))
		if err != nil {
			return nil, err
		}
		publicKey, err := encryrsa.ReadPublicKey(filepath.Join(dir, kid, "public.pem"))
		if err != nil {
			return nil, err
		}
		keys[kid] = RSAKeyPair{
			Private: privateKey,
			Public:  publicKey,
		}
	}
	return keys, nil
}
