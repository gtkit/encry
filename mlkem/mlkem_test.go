package mlkem_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gtkit/encry/mlkem"
	"github.com/stretchr/testify/require"
)

func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	decapSeed, encapKey, err := mlkem.GenerateKeyPair()
	require.NoError(t, err)

	ss1, ct, err := mlkem.Encapsulate(encapKey)
	require.NoError(t, err)
	require.Len(t, ss1, mlkem.SharedKeySize)

	ss2, err := mlkem.Decapsulate(decapSeed, ct)
	require.NoError(t, err)
	require.Equal(t, ss1, ss2)
}

func TestEncapsulateInvalidKey(t *testing.T) {
	_, _, err := mlkem.Encapsulate([]byte("too-short"))
	require.Error(t, err)
}

func TestDecapsulateInvalidSeed(t *testing.T) {
	_, _, ct := mustEncap(t)
	_, err := mlkem.Decapsulate([]byte("bad-seed"), ct)
	require.Error(t, err)
}

func TestDecapsulateTamperedCiphertextImplicitReject(t *testing.T) {
	decapSeed, encapKey, err := mlkem.GenerateKeyPair()
	require.NoError(t, err)
	ss1, ct, err := mlkem.Encapsulate(encapKey)
	require.NoError(t, err)

	// 篡改密文（保持长度）：隐式拒绝——不报错，但共享密钥不同。
	tampered := bytes.Clone(ct)
	tampered[0] ^= 0xff
	ss2, err := mlkem.Decapsulate(decapSeed, tampered)
	require.NoError(t, err)
	require.NotEqual(t, ss1, ss2)
}

func mustEncap(t *testing.T) (decapSeed, ss, ct []byte) {
	t.Helper()
	decapSeed, encapKey, err := mlkem.GenerateKeyPair()
	require.NoError(t, err)
	ss, ct, err = mlkem.Encapsulate(encapKey)
	require.NoError(t, err)
	return decapSeed, ss, ct
}

func ExampleEncapsulate() {
	decapSeed, encapKey, _ := mlkem.GenerateKeyPair()
	ss1, ct, _ := mlkem.Encapsulate(encapKey)
	ss2, _ := mlkem.Decapsulate(decapSeed, ct)
	fmt.Println(bytes.Equal(ss1, ss2))
	// Output: true
}
