package ecdh_test

import (
	stdecdh "crypto/ecdh"
	"fmt"
	"testing"

	"github.com/gtkit/encry/ecdh"
	"github.com/stretchr/testify/require"
)

func TestAgreementSameSecret(t *testing.T) {
	alice, err := ecdh.GenerateX25519()
	require.NoError(t, err)
	bob, err := ecdh.GenerateX25519()
	require.NoError(t, err)

	// Alice 用 Bob 的公钥；Bob 用 Alice 的公钥。
	aliceSS, err := ecdh.SharedSecret(alice, bob.PublicKey())
	require.NoError(t, err)
	bobSS, err := ecdh.SharedSecret(bob, alice.PublicKey())
	require.NoError(t, err)

	require.NotEmpty(t, aliceSS)
	require.Equal(t, aliceSS, bobSS)
}

func TestSerializeRoundTrip(t *testing.T) {
	priv, err := ecdh.GenerateX25519()
	require.NoError(t, err)

	pubBytes := priv.PublicKey().Bytes()
	privBytes := priv.Bytes()

	pub2, err := ecdh.ParsePublicKey(stdecdh.X25519(), pubBytes)
	require.NoError(t, err)
	require.Equal(t, pubBytes, pub2.Bytes())

	priv2, err := ecdh.ParsePrivateKey(stdecdh.X25519(), privBytes)
	require.NoError(t, err)
	require.Equal(t, privBytes, priv2.Bytes())
}

func TestGenerateP256(t *testing.T) {
	priv, err := ecdh.Generate(stdecdh.P256())
	require.NoError(t, err)
	require.NotNil(t, priv.PublicKey())
}

func TestParsePublicKeyInvalid(t *testing.T) {
	_, err := ecdh.ParsePublicKey(stdecdh.X25519(), []byte("too-short"))
	require.Error(t, err)
}

func ExampleSharedSecret() {
	alice, _ := ecdh.GenerateX25519()
	bob, _ := ecdh.GenerateX25519()

	a, _ := ecdh.SharedSecret(alice, bob.PublicKey())
	b, _ := ecdh.SharedSecret(bob, alice.PublicKey())
	fmt.Println(string(a) == string(b))
	// Output: true
}
