package keyring

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/gtkit/encry/ed"
	encryrsa "github.com/gtkit/encry/rsa"
	json "github.com/gtkit/json/v2"
)

// LoadStringKeyRecords 加载带 sidecar metadata 的字符串密钥文件.
func LoadStringKeyRecords(dir, suffix, algorithm, use string) (map[string]Record[string], error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]Record[string], len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		kid := strings.TrimSuffix(entry.Name(), suffix)
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name())) // #nosec G304 -- file name comes from os.ReadDir enumeration under the supplied directory.
		if err != nil {
			return nil, err
		}
		metadata, err := loadMetadata(filepath.Join(dir, kid+".json"), kid, algorithm, use)
		if err != nil {
			return nil, err
		}
		keys[kid] = Record[string]{
			Key:      strings.TrimSpace(string(raw)),
			Metadata: metadata,
		}
	}
	return keys, nil
}

// LoadEd25519KeyPairRecords 从 <dir>/<kid>/{private,public,metadata}.pem/json 加载 Ed25519 密钥对.
func LoadEd25519KeyPairRecords(dir string) (map[string]Record[Ed25519KeyPair], error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]Record[Ed25519KeyPair], len(entries))
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
		metadata, err := loadMetadata(filepath.Join(dir, kid, "metadata.json"), kid, "EdDSA", "sig")
		if err != nil {
			return nil, err
		}
		keys[kid] = Record[Ed25519KeyPair]{
			Key: Ed25519KeyPair{
				Private: privateKey,
				Public:  publicKey,
			},
			Metadata: metadata,
		}
	}
	return keys, nil
}

// LoadRSAKeyPairRecords 从 <dir>/<kid>/{private,public,metadata}.pem/json 加载 RSA 密钥对.
func LoadRSAKeyPairRecords(dir string) (map[string]Record[RSAKeyPair], error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]Record[RSAKeyPair], len(entries))
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
		metadata, err := loadMetadata(filepath.Join(dir, kid, "metadata.json"), kid, "PS512", "sig")
		if err != nil {
			return nil, err
		}
		keys[kid] = Record[RSAKeyPair]{
			Key: RSAKeyPair{
				Private: privateKey,
				Public:  publicKey,
			},
			Metadata: metadata,
		}
	}
	return keys, nil
}

func loadMetadata(path, kid, algorithm, use string) (Metadata, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- metadata path is intentionally constructed by the managed loader.
	if err != nil {
		if os.IsNotExist(err) {
			return Metadata{}.Normalize(kid, algorithm, use), nil
		}
		return Metadata{}, err
	}

	var metadata Metadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return Metadata{}, err
	}
	return metadata.Normalize(kid, algorithm, use), nil
}
