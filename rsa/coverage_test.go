package rsa_test

import (
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
	require.NoError(t, rsa.VerifyPSS(plain, pub, sig))
	require.Error(t, rsa.VerifyPSS([]byte("other"), pub, sig))
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
		err := rsa.VerifyPSSWithPublicKey(nil, []byte("x"), []byte("sig"), crypto.SHA256, nil)
		require.ErrorIs(t, err, rsa.ErrInvalidPublicKey)
	})
	t.Run("verify unsupported hash", func(t *testing.T) {
		t.Parallel()
		err := rsa.VerifyPSSWithPublicKey(pub, []byte("x"), []byte("sig"), crypto.Hash(99), nil)
		require.Error(t, err)
	})
}

func TestPSSBase64DecodeError(t *testing.T) {
	t.Parallel()
	_, pub, _, _ := keyFiles(t)
	err := rsa.VerifyPSSBase64(([]byte("x")), pub, "%%%not-base64%%%")
	require.Error(t, err)
}

func TestPKCS1v15KeyErrors(t *testing.T) {
	t.Parallel()
	_, _, priv, pub := keyFiles(t)

	t.Run("encrypt nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.EncryptPKCS1v15(nil, []byte("x"))
		require.ErrorIs(t, err, rsa.ErrInvalidPublicKey)
	})
	t.Run("encrypt too long", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.EncryptPKCS1v15(pub, make([]byte, 1000))
		require.Error(t, err)
	})
	t.Run("decrypt nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptPKCS1v15(nil, []byte("x"))
		require.ErrorIs(t, err, rsa.ErrInvalidPrivateKey)
	})
	t.Run("decrypt empty", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.DecryptPKCS1v15(priv, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
	t.Run("decrypt too long", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptPKCS1v15(priv, make([]byte, priv.Size()+1))
		require.ErrorIs(t, err, rsa.ErrCipherTextTooLong)
	})
	t.Run("decrypt wrong size", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptPKCS1v15(priv, make([]byte, priv.Size()-1))
		require.Error(t, err)
	})
}

func TestPKCS1v15ChunkedKeyErrors(t *testing.T) {
	t.Parallel()
	_, _, priv, pub := keyFiles(t)

	t.Run("encrypt nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.EncryptPKCS1v15Chunked(nil, []byte("x"))
		require.ErrorIs(t, err, rsa.ErrInvalidPublicKey)
	})
	t.Run("encrypt empty", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.EncryptPKCS1v15Chunked(pub, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
	t.Run("decrypt nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptPKCS1v15Chunked(nil, []byte("x"))
		require.ErrorIs(t, err, rsa.ErrInvalidPrivateKey)
	})
	t.Run("decrypt empty", func(t *testing.T) {
		t.Parallel()
		got, err := rsa.DecryptPKCS1v15Chunked(priv, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
	t.Run("decrypt misaligned", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.DecryptPKCS1v15Chunked(priv, make([]byte, priv.Size()+1))
		require.Error(t, err)
	})
}

func TestPKCS1v15Base64DecodeErrors(t *testing.T) {
	t.Parallel()
	_, _, priv, _ := keyFiles(t)

	_, err := rsa.DecryptPKCS1v15Base64(priv, "%%%not-base64%%%")
	require.Error(t, err)
	_, err = rsa.DecryptPKCS1v15ChunkedBase64(priv, "%%%not-base64%%%")
	require.Error(t, err)
}

func TestPKCS1DeprecatedBlockBytes(t *testing.T) {
	t.Parallel()
	pri, pub, _, _ := keyFiles(t)
	plain := []byte(strings.Repeat("block-", 100))

	cipherBytes, err := rsa.EncryptBlockBytes(plain, pub)
	require.NoError(t, err)
	decrypted, err := rsa.DecryptBlock(cipherBytes, pri)
	require.NoError(t, err)
	require.Equal(t, plain, decrypted)
}

func TestPKCS1DeprecatedFileErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope.pem")

	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "Encrypt", fn: func() error { _, err := rsa.Encrypt([]byte("x"), missing); return err }},
		{name: "EncryptToBase64", fn: func() error { _, err := rsa.EncryptToBase64([]byte("x"), missing); return err }},
		{name: "Decrypt", fn: func() error { _, err := rsa.Decrypt([]byte("x"), missing); return err }},
		{name: "DecryptBase64", fn: func() error { _, err := rsa.DecryptBase64("eA==", missing); return err }},
		{name: "EncryptBlock", fn: func() error { _, err := rsa.EncryptBlock([]byte("x"), missing); return err }},
		{name: "EncryptBlockBytes", fn: func() error { _, err := rsa.EncryptBlockBytes([]byte("x"), missing); return err }},
		{name: "DecryptBlock", fn: func() error { _, err := rsa.DecryptBlock([]byte("x"), missing); return err }},
		{name: "DecryptBlockBase64", fn: func() error { _, err := rsa.DecryptBlockBase64("eA==", missing); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, tt.fn())
		})
	}
}

func TestSignLegacyHashHelpers(t *testing.T) {
	t.Parallel()
	pri, pub, _, _ := keyFiles(t)
	plain := []byte("legacy-sign")

	t.Run("SignSHA256/VerifySHA256", func(t *testing.T) {
		t.Parallel()
		sig, err := rsa.SignSHA256(plain, pri)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifySHA256(plain, pub, sig))
	})
	t.Run("SignSHA512Base64/VerifySHA512Base64", func(t *testing.T) {
		t.Parallel()
		sig, err := rsa.SignSHA512Base64(plain, pri)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifySHA512Base64(plain, pub, sig))
	})
	t.Run("SignSHA1/VerifySHA1", func(t *testing.T) {
		t.Parallel()
		sig, err := rsa.SignSHA1(plain, pri)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifySHA1(plain, pub, sig))
	})
	t.Run("SignMD5/VerifyMD5Bytes", func(t *testing.T) {
		t.Parallel()
		sig, err := rsa.SignMD5(plain, pri)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyMD5Bytes(plain, pub, sig))
	})
	t.Run("SignMD5Base64/VerifyMD5", func(t *testing.T) {
		t.Parallel()
		sig, err := rsa.SignMD5Base64(plain, pri)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyMD5(string(plain), sig, pub))
	})
}

func TestSignPKCS1v15KeyErrors(t *testing.T) {
	t.Parallel()
	_, _, priv, pub := keyFiles(t)

	t.Run("sign nil key", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.SignPKCS1v15(nil, []byte("x"), crypto.SHA256)
		require.ErrorIs(t, err, rsa.ErrInvalidPrivateKey)
	})
	t.Run("sign unsupported hash", func(t *testing.T) {
		t.Parallel()
		_, err := rsa.SignPKCS1v15(priv, []byte("x"), crypto.Hash(99))
		require.ErrorIs(t, err, rsa.ErrUnsupportedHash)
	})
	t.Run("verify nil key", func(t *testing.T) {
		t.Parallel()
		err := rsa.VerifyPKCS1v15(nil, []byte("x"), []byte("sig"), crypto.SHA256)
		require.ErrorIs(t, err, rsa.ErrInvalidPublicKey)
	})
	t.Run("verify unsupported hash", func(t *testing.T) {
		t.Parallel()
		err := rsa.VerifyPKCS1v15(pub, []byte("x"), []byte("sig"), crypto.Hash(99))
		require.ErrorIs(t, err, rsa.ErrUnsupportedHash)
	})
}

func TestSignPKCS1v15Base64DecodeError(t *testing.T) {
	t.Parallel()
	_, _, _, pub := keyFiles(t)
	err := rsa.VerifyPKCS1v15Base64(pub, []byte("x"), "%%%not-base64%%%", crypto.SHA256)
	require.Error(t, err)
}

func TestSignCS8MD5Error(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope.pem")
	_, err := rsa.SignCS8MD5("msg", missing)
	require.Error(t, err)
}

func TestSignFileLevelErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "nope.pem")

	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "Sign", fn: func() error { _, err := rsa.Sign([]byte("x"), missing); return err }},
		{name: "Verify", fn: func() error { return rsa.Verify([]byte("x"), missing, []byte("sig")) }},
		{name: "SignBase64WithHash", fn: func() error {
			_, err := rsa.SignBase64WithHash([]byte("x"), missing, crypto.SHA256)
			return err
		}},
		{name: "VerifyBase64WithHash", fn: func() error {
			return rsa.VerifyBase64WithHash([]byte("x"), missing, "c2ln", crypto.SHA256)
		}},
		{name: "SignSHA256Base64", fn: func() error { _, err := rsa.SignSHA256Base64([]byte("x"), missing); return err }},
		{name: "VerifySHA256Base64", fn: func() error { return rsa.VerifySHA256Base64([]byte("x"), missing, "c2ln") }},
		{name: "SignPSSBase64", fn: func() error { _, err := rsa.SignPSSBase64([]byte("x"), missing); return err }},
		{name: "EncryptOAEPBase64", fn: func() error { _, err := rsa.EncryptOAEPBase64([]byte("x"), missing); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, tt.fn())
		})
	}
}
