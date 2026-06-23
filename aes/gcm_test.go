package aes_test

import (
	"testing"

	"github.com/gtkit/encry/aes"
	"github.com/stretchr/testify/require"
)

func TestGCMEncryptDecrypt(t *testing.T) {
	const key = "IgkibX71IEf382PT"

	tests := []struct {
		name      string
		plainText []byte
		aad       []byte
	}{
		{name: "simple", plainText: []byte("hello-gcm"), aad: nil},
		{name: "with aad", plainText: []byte("hello-gcm"), aad: []byte("order:1001")},
		{name: "empty plaintext", plainText: []byte(""), aad: []byte("aad")},
		{name: "binary", plainText: []byte{0x00, 0x01, 0xff}, aad: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gcm := aes.NewGCM(key)

			cipherText, err := gcm.EncryptWithAAD(tt.plainText, tt.aad)
			require.NoError(t, err)

			got, err := gcm.DecryptWithAAD(cipherText, tt.aad)
			require.NoError(t, err)
			require.Equal(t, string(tt.plainText), string(got))
		})
	}
}
