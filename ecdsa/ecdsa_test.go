package ecdsa_test

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/gtkit/encry/ecdsa"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey()
	require.NoError(t, err)

	msg := []byte("message to sign")
	sig, err := ecdsa.Sign(priv, msg)
	require.NoError(t, err)

	ok, err := ecdsa.Verify(&priv.PublicKey, msg, sig)
	require.NoError(t, err)
	require.True(t, ok)

	// 篡改消息验签失败。
	bad, err := ecdsa.Verify(&priv.PublicKey, []byte("tampered"), sig)
	require.NoError(t, err)
	require.False(t, bad)
}

func TestSignVerifyBase64(t *testing.T) {
	priv, err := ecdsa.GenerateKeyWithCurve(elliptic.P384())
	require.NoError(t, err)

	msg := []byte("payload")
	sigB64, err := ecdsa.SignBase64(priv, msg)
	require.NoError(t, err)

	ok, err := ecdsa.VerifyBase64(&priv.PublicKey, msg, sigB64)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestVerifyBase64InvalidEncoding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey()
	_, err := ecdsa.VerifyBase64(&priv.PublicKey, []byte("m"), "!!!notb64!!!")
	require.Error(t, err)
}

func TestNilKeys(t *testing.T) {
	_, err := ecdsa.Sign(nil, []byte("m"))
	require.ErrorIs(t, err, ecdsa.ErrInvalidPrivateKey)

	ok, err := ecdsa.Verify(nil, []byte("m"), []byte("sig"))
	require.ErrorIs(t, err, ecdsa.ErrInvalidPublicKey)
	require.False(t, ok)
}

func TestPEMRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey()
	require.NoError(t, err)

	privPEM, err := ecdsa.MarshalPrivateKeyPEM(priv)
	require.NoError(t, err)
	pubPEM, err := ecdsa.MarshalPublicKeyPEM(&priv.PublicKey)
	require.NoError(t, err)

	priv2, err := ecdsa.ParsePrivateKeyPEM(privPEM)
	require.NoError(t, err)
	pub2, err := ecdsa.ParsePublicKeyPEM(pubPEM)
	require.NoError(t, err)

	// 用解析回来的密钥继续签名验签。
	sig, err := ecdsa.Sign(priv2, []byte("x"))
	require.NoError(t, err)
	ok, err := ecdsa.Verify(pub2, []byte("x"), sig)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestParsePEMErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"非PEM", []byte("not a pem")},
		{"空", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ecdsa.ParsePrivateKeyPEM(tt.data)
			require.Error(t, err)
			_, err = ecdsa.ParsePublicKeyPEM(tt.data)
			require.Error(t, err)
		})
	}
}

func ExampleSign() {
	priv, _ := ecdsa.GenerateKey()
	sig, _ := ecdsa.Sign(priv, []byte("hello"))
	ok, _ := ecdsa.Verify(&priv.PublicKey, []byte("hello"), sig)
	fmt.Println(ok)
	// Output: true
}
