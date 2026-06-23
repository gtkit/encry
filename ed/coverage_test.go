package ed_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtkit/encry/ed"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyLegacy(t *testing.T) {
	t.Parallel()

	// Deprecated 接口：每次调用生成临时密钥对，公钥与签名同源，应能自验。
	pub, sig := ed.Sign("legacy-msg")
	require.NotEmpty(t, pub)
	require.NotEmpty(t, sig)

	tests := []struct {
		name string
		pub  string
		msg  string
		sig  string
		want bool
	}{
		{name: "valid", pub: pub, msg: "legacy-msg", sig: sig, want: true},
		{name: "wrong message", pub: pub, msg: "tampered", sig: sig, want: false},
		{name: "invalid public key length", pub: "short", msg: "legacy-msg", sig: sig, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, ed.Verify(tt.pub, tt.msg, tt.sig))
		})
	}
}

func TestMarshalPrivateKeyPEMErrors(t *testing.T) {
	t.Parallel()

	_, priv, err := ed.GenerateKeyPair()
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     ed25519.PrivateKey
		wantErr bool
	}{
		{name: "valid", key: priv, wantErr: false},
		{name: "too short", key: ed25519.PrivateKey{1, 2, 3}, wantErr: true},
		{name: "nil", key: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ed.MarshalPrivateKeyPEM(tt.key)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, got)
		})
	}
}

func TestMarshalPublicKeyPEMErrors(t *testing.T) {
	t.Parallel()

	pub, _, err := ed.GenerateKeyPair()
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     ed25519.PublicKey
		wantErr bool
	}{
		{name: "valid", key: pub, wantErr: false},
		{name: "too short", key: ed25519.PublicKey{1, 2, 3}, wantErr: true},
		{name: "nil", key: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ed.MarshalPublicKeyPEM(tt.key)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, got)
		})
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	t.Parallel()

	_, priv, err := ed.GenerateKeyPair()
	require.NoError(t, err)
	validPEM, err := ed.MarshalPrivateKeyPEM(priv)
	require.NoError(t, err)

	// 自定义 "ED25519 PRIVATE KEY" 块（合法长度）。
	rawBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: []byte(priv),
	})
	// 自定义块但长度非法。
	rawBlockBad := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: []byte{1, 2, 3},
	})
	// PKCS#8 内含非 Ed25519 密钥（用 RSA），类型断言失败。
	wrongType := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte{1, 2, 3},
	})

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid pkcs8", data: validPEM, wantErr: false},
		{name: "valid raw ed25519 block", data: rawBlock, wantErr: false},
		{name: "raw block bad length", data: rawBlockBad, wantErr: true},
		{name: "not a pem block", data: []byte("not-a-pem"), wantErr: true},
		{name: "unknown block type", data: wrongType, wantErr: true},
		{name: "pkcs8 garbage bytes", data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0, 1, 2}}), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ed.ParsePrivateKeyPEM(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, ed25519.PrivateKeySize)
		})
	}
}

// TestParseKeyPEMWrongKeyType 用 PKCS#8/PKIX 包装的非 Ed25519 密钥，触发 ed25519 类型断言失败分支。
func TestParseKeyPEMWrongKeyType(t *testing.T) {
	t.Parallel()

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalPKCS8PrivateKey(ecPriv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	_, err = ed.ParsePrivateKeyPEM(privPEM)
	require.ErrorIs(t, err, ed.ErrInvalidPrivateKey)

	_, err = ed.ParsePublicKeyPEM(pubPEM)
	require.ErrorIs(t, err, ed.ErrInvalidPublicKey)
}

func TestParsePublicKeyPEM(t *testing.T) {
	t.Parallel()

	pub, _, err := ed.GenerateKeyPair()
	require.NoError(t, err)
	validPEM, err := ed.MarshalPublicKeyPEM(pub)
	require.NoError(t, err)

	rawBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: []byte(pub),
	})
	rawBlockBad := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: []byte{1, 2, 3},
	})

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid pkix", data: validPEM, wantErr: false},
		{name: "valid raw ed25519 block", data: rawBlock, wantErr: false},
		{name: "raw block bad length", data: rawBlockBad, wantErr: true},
		{name: "not a pem block", data: []byte("not-a-pem"), wantErr: true},
		{name: "unknown block type", data: pem.EncodeToMemory(&pem.Block{Type: "WHATEVER", Bytes: []byte{1}}), wantErr: true},
		{name: "pkix garbage bytes", data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0, 1, 2}}), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ed.ParsePublicKeyPEM(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, ed25519.PublicKeySize)
		})
	}
}

func TestSignBytesErrors(t *testing.T) {
	t.Parallel()

	_, priv, err := ed.GenerateKeyPair()
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     ed25519.PrivateKey
		wantErr bool
	}{
		{name: "valid", key: priv, wantErr: false},
		{name: "invalid length", key: ed25519.PrivateKey{1, 2}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ed.SignBytes(tt.key, []byte("msg"))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSignBase64Error(t *testing.T) {
	t.Parallel()
	_, err := ed.SignBase64(ed25519.PrivateKey{1, 2}, []byte("msg"))
	require.Error(t, err)
}

func TestVerifyBytesAndBase64(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed.GenerateKeyPair()
	require.NoError(t, err)
	sig, err := ed.SignBytes(priv, []byte("msg"))
	require.NoError(t, err)
	sigB64, err := ed.SignBase64(priv, []byte("msg"))
	require.NoError(t, err)

	tests := []struct {
		name string
		fn   func() bool
		want bool
	}{
		{name: "verify bytes ok", fn: func() bool { return ed.VerifyBytes(pub, []byte("msg"), sig) }, want: true},
		{name: "verify bytes bad pub len", fn: func() bool { return ed.VerifyBytes(ed25519.PublicKey{1}, []byte("msg"), sig) }, want: false},
		{name: "verify base64 ok", fn: func() bool { return ed.VerifyBase64(pub, []byte("msg"), sigB64) }, want: true},
		{name: "verify base64 invalid encoding", fn: func() bool { return ed.VerifyBase64(pub, []byte("msg"), "%%%") }, want: false},
		{name: "verify base64 wrong msg", fn: func() bool { return ed.VerifyBase64(pub, []byte("other"), sigB64) }, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, tt.fn())
		})
	}
}

func TestFileOperationErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.pem")

	t.Run("read private missing file", func(t *testing.T) {
		t.Parallel()
		_, err := ed.ReadPrivateKey(missing)
		require.Error(t, err)
	})
	t.Run("read public missing file", func(t *testing.T) {
		t.Parallel()
		_, err := ed.ReadPublicKey(missing)
		require.Error(t, err)
	})
	t.Run("sign file missing", func(t *testing.T) {
		t.Parallel()
		_, err := ed.SignFile([]byte("m"), missing)
		require.Error(t, err)
	})
	t.Run("sign file base64 missing", func(t *testing.T) {
		t.Parallel()
		_, err := ed.SignFileBase64([]byte("m"), missing)
		require.Error(t, err)
	})
	t.Run("verify file missing", func(t *testing.T) {
		t.Parallel()
		_, err := ed.VerifyFile([]byte("m"), missing, []byte("sig"))
		require.Error(t, err)
	})
	t.Run("verify file base64 missing", func(t *testing.T) {
		t.Parallel()
		_, err := ed.VerifyFileBase64([]byte("m"), missing, "c2ln")
		require.Error(t, err)
	})
}

func TestSignVerifyFileBase64RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	require.NoError(t, ed.WriteKeyPair(privatePath, publicPath))

	sig, err := ed.SignFileBase64([]byte("file-msg"), privatePath)
	require.NoError(t, err)

	ok, err := ed.VerifyFileBase64([]byte("file-msg"), publicPath, sig)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = ed.VerifyFileBase64([]byte("wrong"), publicPath, sig)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestWriteKeyPairError(t *testing.T) {
	t.Parallel()

	// 把私钥路径指向一个已存在的文件作为目录，使 MkdirAll 失败。
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "afile")
	require.NoError(t, os.WriteFile(fileAsDir, []byte("x"), 0o600))

	// privatePath 的父目录是一个普通文件，MkdirAll 应失败。
	badPath := filepath.Join(fileAsDir, "sub", "private.pem")
	err := ed.WriteKeyPair(badPath, filepath.Join(dir, "public.pem"))
	require.Error(t, err)
}

func TestGenerateKeyPEM(t *testing.T) {
	t.Parallel()

	privatePEM, publicPEM, err := ed.GenerateKeyPEM()
	require.NoError(t, err)
	require.NotEmpty(t, privatePEM)
	require.NotEmpty(t, publicPEM)

	priv, err := ed.ParsePrivateKeyPEM(privatePEM)
	require.NoError(t, err)
	pub, err := ed.ParsePublicKeyPEM(publicPEM)
	require.NoError(t, err)

	sig, err := ed.SignBytes(priv, []byte("roundtrip"))
	require.NoError(t, err)
	require.True(t, ed.VerifyBytes(pub, []byte("roundtrip"), sig))
}
