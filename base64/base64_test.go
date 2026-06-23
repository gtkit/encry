package base64_test

import (
	"testing"

	encrybase64 "github.com/gtkit/encry/base64"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []byte
		encode func([]byte) string
		decode func(string) ([]byte, error)
		want   string
	}{
		{
			name:   "std empty",
			input:  []byte(""),
			encode: encrybase64.Encode,
			decode: encrybase64.Decode,
			want:   "",
		},
		{
			name:   "std hello",
			input:  []byte("hello"),
			encode: encrybase64.Encode,
			decode: encrybase64.Decode,
			want:   "aGVsbG8=",
		},
		{
			name:   "std encode alias",
			input:  []byte("foobar"),
			encode: encrybase64.StdEncode,
			decode: encrybase64.StdDecode,
			want:   "Zm9vYmFy",
		},
		{
			name:   "url with special bytes",
			input:  []byte{0xfb, 0xff, 0xbf},
			encode: encrybase64.URLEncode,
			decode: encrybase64.URLDecode,
			want:   "-_-_",
		},
		{
			name:   "raw std no padding",
			input:  []byte("hello"),
			encode: encrybase64.RawStdEncode,
			decode: encrybase64.RawStdDecode,
			want:   "aGVsbG8",
		},
		{
			name:   "raw url no padding",
			input:  []byte{0xfb, 0xff, 0xbf},
			encode: encrybase64.RawURLEncode,
			decode: encrybase64.RawURLDecode,
			want:   "-_-_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.encode(tt.input)
			require.Equal(t, tt.want, got)

			decoded, err := tt.decode(got)
			require.NoError(t, err)
			require.Equal(t, tt.input, decoded)
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		decode func(string) ([]byte, error)
	}{
		{"std illegal char", "****", encrybase64.Decode},
		{"std alias illegal char", "****", encrybase64.StdDecode},
		{"std wrong padding", "aGVsbG8", encrybase64.StdDecode},
		{"url illegal char", "++++", encrybase64.URLDecode},
		{"raw std illegal char", "****", encrybase64.RawStdDecode},
		{"raw url illegal char", "////", encrybase64.RawURLDecode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.decode(tt.input)
			require.Error(t, err)
		})
	}
}
