package hpke_test

import (
	"fmt"
	"testing"

	"github.com/gtkit/encry/hpke"
	"github.com/stretchr/testify/require"
)

func TestSealOpenRoundTrip(t *testing.T) {
	priv, err := hpke.GenerateKeyPair()
	require.NoError(t, err)

	info := []byte("app:context")
	plain := []byte("secret message")

	enc, err := hpke.Seal(priv.PublicKey(), info, plain)
	require.NoError(t, err)
	require.NotEmpty(t, enc)

	got, err := hpke.Open(priv, info, enc)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func TestSealOpenViaSerializedPublicKey(t *testing.T) {
	priv, err := hpke.GenerateKeyPair()
	require.NoError(t, err)

	// 发送方仅拿到接收方公钥字节。
	pubBytes := priv.PublicKey().Bytes()
	pub, err := hpke.ParsePublicKey(pubBytes)
	require.NoError(t, err)

	enc, err := hpke.Seal(pub, nil, []byte("data"))
	require.NoError(t, err)
	got, err := hpke.Open(priv, nil, enc)
	require.NoError(t, err)
	require.Equal(t, []byte("data"), got)
}

func TestOpenInfoMismatch(t *testing.T) {
	priv, _ := hpke.GenerateKeyPair()
	enc, err := hpke.Seal(priv.PublicKey(), []byte("info-a"), []byte("x"))
	require.NoError(t, err)

	_, err = hpke.Open(priv, []byte("info-b"), enc)
	require.Error(t, err)
}

func TestOpenWrongKey(t *testing.T) {
	priv, _ := hpke.GenerateKeyPair()
	other, _ := hpke.GenerateKeyPair()
	enc, err := hpke.Seal(priv.PublicKey(), nil, []byte("x"))
	require.NoError(t, err)

	_, err = hpke.Open(other, nil, enc)
	require.Error(t, err)
}

func TestOpenInvalidBase64(t *testing.T) {
	priv, _ := hpke.GenerateKeyPair()
	_, err := hpke.Open(priv, nil, "!!!notb64!!!")
	require.Error(t, err)
}

func TestParsePublicKeyInvalid(t *testing.T) {
	_, err := hpke.ParsePublicKey([]byte("short"))
	require.Error(t, err)
}

func ExampleSeal() {
	priv, _ := hpke.GenerateKeyPair()

	// 发送方只需接收方公钥。
	enc, _ := hpke.Seal(priv.PublicKey(), []byte("ctx"), []byte("hello"))
	// 接收方用私钥解密。
	got, _ := hpke.Open(priv, []byte("ctx"), enc)
	fmt.Println(string(got))
	// Output: hello
}
