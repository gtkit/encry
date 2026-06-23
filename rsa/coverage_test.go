package rsa_test

import (
	"context"
	"crypto"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtkit/encry/rsa"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPairContext(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		priv, pub, err := rsa.GenerateKeyPairContext(context.Background(), 2048)
		require.NoError(t, err)
		require.NotNil(t, priv)
		require.NotNil(t, pub)
	})

	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := rsa.GenerateKeyPairContext(ctx, 4096)
		require.ErrorIs(t, err, context.Canceled)
	})
}

// keyFiles 在临时目录生成 PKCS#1 PEM 密钥对，返回私钥/公钥文件路径与解析后的密钥。
func keyFiles(t *testing.T) (priPath, pubPath string, priv *stdrsa.PrivateKey, pub *stdrsa.PublicKey) {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, rsa.GenerateRsaKey(2048, dir))
	priPath = filepath.Join(dir, "private.pem")
	pubPath = filepath.Join(dir, "public.pem")

	var err error
	priv, err = rsa.ReadPrivateKey(priPath)
	require.NoError(t, err)
	pub, err = rsa.ReadPublicKey(pubPath)
	require.NoError(t, err)
	return priPath, pubPath, priv, pub
}

func TestGetKey(t *testing.T) {
	t.Parallel()

	pri, pub, _, _ := keyFiles(t)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "private key", path: pri, wantErr: false},
		{name: "public key", path: pub, wantErr: false},
		{name: "missing file", path: filepath.Join(t.TempDir(), "nope.pem"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			block, err := rsa.GetKey(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, block)
		})
	}
}

func TestError(t *testing.T) {
	t.Parallel()
	err := rsa.Error("file.go", 42, "boom")
	require.Error(t, err)
	require.Contains(t, err.Error(), "file.go")
	require.Contains(t, err.Error(), "42")
	require.Contains(t, err.Error(), "boom")
}

func TestGenerateRsaKeyError(t *testing.T) {
	t.Parallel()
	// keySize 过小会让 GenerateKey 失败。
	err := rsa.GenerateRsaKey(1, t.TempDir())
	require.Error(t, err)
}

func TestGenerateRsaKeyWriteError(t *testing.T) {
	t.Parallel()
	// 把目标目录设置为一个已存在的普通文件路径下的子目录，MkdirAll 失败。
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "afile")
	require.NoError(t, os.WriteFile(fileAsDir, []byte("x"), 0o600))
	err := rsa.GenerateRsaKey(2048, filepath.Join(fileAsDir, "sub"))
	require.Error(t, err)
}

func TestParseKeyPEMInline(t *testing.T) {
	t.Parallel()

	_, _, priv, pub := keyFiles(t)
	privPEM := rsa.MarshalPKCS1PrivateKeyPEM(priv)
	pubPEM := rsa.MarshalPKCS1PublicKeyPEM(pub)
	pkixPEM, err := rsa.MarshalPKIXPublicKeyPEM(pub)
	require.NoError(t, err)

	t.Run("parse private valid", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.ParsePrivateKeyPEM(privPEM)
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("parse private invalid pem", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.ParsePrivateKeyPEM([]byte("not-a-pem"))
		require.ErrorIs(t, err, rsa.ErrInvalidPEMBlock)
	})
	t.Run("parse public pkcs1 valid", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.ParsePublicKeyPEM(pubPEM)
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("parse public pkix valid", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.ParsePublicKeyPEM(pkixPEM)
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("parse public invalid pem", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.ParsePublicKeyPEM([]byte("not-a-pem"))
		require.ErrorIs(t, err, rsa.ErrInvalidPEMBlock)
	})
}

// TestParseKeyBlockBranches 覆盖 parsePrivateKeyBlock/parsePublicKeyBlock 的多种 PEM 块类型分支。
func TestParseKeyBlockBranches(t *testing.T) {
	t.Parallel()

	_, _, priv, pub := keyFiles(t)

	// "PRIVATE KEY"（PKCS#8）私钥。
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	// 自定义 block 类型（default 分支）承载 PKCS#1 私钥。
	customPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "WHATEVER KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// "PUBLIC KEY"（PKIX）公钥。
	pkixDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pkixPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})

	// 自定义 block 类型（default 分支）承载 PKCS#1 公钥。
	customPubPEM := pem.EncodeToMemory(&pem.Block{Type: "WHATEVER KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)})

	// "RSA PRIVATE KEY" 块但内容非法 -> 私钥解析失败。
	badPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{0, 1, 2}})
	// "RSA PUBLIC KEY" 块但内容非法 -> 公钥解析失败。
	badPubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte{0, 1, 2}})

	privTests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "pkcs8 private", data: pkcs8PEM, wantErr: false},
		{name: "custom block private", data: customPrivPEM, wantErr: false},
		{name: "bad rsa private", data: badPrivPEM, wantErr: true},
	}
	for _, tt := range privTests {
		t.Run("private/"+tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := rsa.ParsePrivateKeyPEM(tt.data)
			if tt.wantErr {
				require.ErrorIs(t, err, rsa.ErrInvalidPrivateKey)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}

	pubTests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "pkix public", data: pkixPEM, wantErr: false},
		{name: "custom block public", data: customPubPEM, wantErr: false},
		{name: "bad rsa public", data: badPubPEM, wantErr: true},
	}
	for _, tt := range pubTests {
		t.Run("public/"+tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := rsa.ParsePublicKeyPEM(tt.data)
			if tt.wantErr {
				require.ErrorIs(t, err, rsa.ErrInvalidPublicKey)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func TestReadKeyErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope.pem")

	_, err := rsa.ReadPrivateKey(missing)
	require.Error(t, err)
	_, err = rsa.ReadPublicKey(missing)
	require.Error(t, err)
}

func TestOAEPDeprecatedWrappers(t *testing.T) {
	t.Parallel()

	pri, pub, _, _ := keyFiles(t)
	plain := []byte("oaep-deprecated")

	cipherBytes, err := rsa.EncryptOAEP(plain, pub)
	require.NoError(t, err)
	decrypted, err := rsa.DecryptOAEP(cipherBytes, pri)
	require.NoError(t, err)
	require.Equal(t, plain, decrypted)

	chunkPlain := []byte(strings.Repeat("oaep-chunk-", 60))
	chunkCipher, err := rsa.EncryptOAEPChunked(chunkPlain, pub)
	require.NoError(t, err)
	chunkDecrypted, err := rsa.DecryptOAEPChunked(chunkCipher, pri)
	require.NoError(t, err)
	require.Equal(t, chunkPlain, chunkDecrypted)
}

func TestEncryptOAEPWithPublicKeyErrors(t *testing.T) {
	t.Parallel()

	_, _, _, pub := keyFiles(t)

	tests := []struct {
		name      string
		key       *stdrsa.PublicKey
		plainText []byte
		hash      crypto.Hash
		wantErr   bool
	}{
		{name: "success", key: pub, plainText: []byte("hi"), hash: crypto.SHA256, wantErr: false},
		{name: "nil key", key: nil, plainText: []byte("hi"), hash: crypto.SHA256, wantErr: true},
		{name: "unavailable hash", key: pub, plainText: []byte("hi"), hash: crypto.MD4, wantErr: true},
		{name: "message too long", key: pub, plainText: make([]byte, 1000), hash: crypto.SHA256, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := rsa.EncryptOAEPWithPublicKey(tt.key, tt.plainText, tt.hash, nil)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDecryptOAEPWithPrivateKeyErrors(t *testing.T) {
	t.Parallel()

	_, _, priv, _ := keyFiles(t)

	tests := []struct {
		name       string
		key        *stdrsa.PrivateKey
		cipherText []byte
		hash       crypto.Hash
		wantErr    bool
	}{
		{name: "nil key", key: nil, cipherText: []byte("x"), hash: crypto.SHA256, wantErr: true},
		{name: "unavailable hash", key: priv, cipherText: make([]byte, priv.Size()), hash: crypto.MD4, wantErr: true},
		{name: "empty ciphertext returns empty", key: priv, cipherText: nil, hash: crypto.SHA256, wantErr: false},
		{name: "wrong size", key: priv, cipherText: []byte("short"), hash: crypto.SHA256, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := rsa.DecryptOAEPWithPrivateKey(tt.key, tt.cipherText, tt.hash, nil)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestOAEPChunkedKeyErrors(t *testing.T) {
	t.Parallel()

	_, _, priv, pub := keyFiles(t)

	t.Run("encrypt nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.EncryptOAEPChunkedWithPublicKey(nil, []byte("x"), crypto.SHA256, nil)
		require.Error(t, err)
	})
	t.Run("encrypt unavailable hash", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.EncryptOAEPChunkedWithPublicKey(pub, []byte("x"), crypto.MD4, nil)
		require.Error(t, err)
	})
	t.Run("encrypt empty plaintext", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.EncryptOAEPChunkedWithPublicKey(pub, nil, crypto.SHA256, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
	t.Run("decrypt nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptOAEPChunkedWithPrivateKey(nil, []byte("x"), crypto.SHA256, nil)
		require.Error(t, err)
	})
	t.Run("decrypt unavailable hash", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptOAEPChunkedWithPrivateKey(priv, make([]byte, priv.Size()), crypto.MD4, nil)
		require.Error(t, err)
	})
	t.Run("decrypt empty ciphertext", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.DecryptOAEPChunkedWithPrivateKey(priv, nil, crypto.SHA256, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
	t.Run("decrypt misaligned", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptOAEPChunkedWithPrivateKey(priv, make([]byte, priv.Size()+1), crypto.SHA256, nil)
		require.Error(t, err)
	})
}

func TestOAEPBase64DecodeError(t *testing.T) {
	t.Parallel()
	pri, _, _, _ := keyFiles(t)

	_, err := rsa.DecryptOAEPBase64("%%%not-base64%%%", pri)
	require.Error(t, err)
	_, err = rsa.DecryptOAEPChunkedBase64("%%%not-base64%%%", pri)
	require.Error(t, err)
}

func TestPSSDeprecatedWrappers(t *testing.T) {
	t.Parallel()
	pri, pub, _, _ := keyFiles(t)
	plain := []byte("pss-default")

	sig, err := rsa.SignPSS(plain, pri)
	require.NoError(t, err)

	ok, err := rsa.VerifyPSS(plain, pub, sig)
	require.NoError(t, err)
	require.True(t, ok)

	bad, err := rsa.VerifyPSS([]byte("other"), pub, sig)
	require.NoError(t, err)
	require.False(t, bad)
}

func TestPSSKeyErrors(t *testing.T) {
	t.Parallel()
	_, _, priv, pub := keyFiles(t)

	t.Run("sign nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.SignPSSWithPrivateKey(nil, []byte("x"), crypto.SHA256, nil)
		require.ErrorIs(t, err, rsa.ErrInvalidPrivateKey)
	})
	t.Run("sign unsupported hash", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.SignPSSWithPrivateKey(priv, []byte("x"), crypto.Hash(99), nil)
		require.Error(t, err)
	})
	t.Run("verify nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.VerifyPSSWithPublicKey(nil, []byte("x"), []byte("sig"), crypto.SHA256, nil)
		require.ErrorIs(t, err, rsa.ErrInvalidPublicKey)
	})
	t.Run("verify unsupported hash", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.VerifyPSSWithPublicKey(pub, []byte("x"), []byte("sig"), crypto.Hash(99), nil)
		require.Error(t, err)
	})
}

func TestPSSBase64DecodeError(t *testing.T) {
	t.Parallel()
	_, pub, _, _ := keyFiles(t)
	_, err := rsa.VerifyPSSBase64(([]byte("x")), pub, "%%%not-base64%%%")
	require.Error(t, err)
}
