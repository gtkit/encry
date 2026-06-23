package sealer

import (
	"errors"
	"testing"

	encryaes "github.com/gtkit/encry/aes"
	"github.com/gtkit/encry/internal/keyring"
)

const (
	testKID    = "k1"
	testKey    = "0123456789abcdef0123456789abcdef" // 32 bytes -> AES-256
	testKeyAlt = "abcdef0123456789abcdef0123456789" // 不同 32 字节密钥
	shortKey   = "tooshort"                         // 8 字节 -> 非法 AES key 长度
)

func newStringRing(t *testing.T, keys map[string]string) *keyring.Ring[string] {
	t.Helper()
	ring := keyring.New[string]()
	if err := ring.Store(testKID, keys); err != nil {
		t.Fatalf("store ring: %v", err)
	}
	return ring
}

func TestAESGCMService_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		plainText []byte
		aad       []byte
	}{
		{name: "simple", plainText: []byte("hello world"), aad: nil},
		{name: "with aad", plainText: []byte("payload"), aad: []byte("context")},
		{name: "empty plaintext", plainText: []byte(""), aad: []byte("aad")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring := newStringRing(t, map[string]string{testKID: testKey})
			svc := NewAESGCM(ring)

			token, err := svc.Encrypt(tt.plainText, tt.aad)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if got := token[:len(testKID)+1]; got != testKID+"." {
				t.Errorf("token kid prefix = %q, want %q", got, testKID+".")
			}

			got, err := svc.Decrypt(token, tt.aad)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(got) != string(tt.plainText) {
				t.Errorf("round-trip = %q, want %q", got, tt.plainText)
			}
		})
	}
}

func TestAESGCMService_Encrypt_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ring    func(t *testing.T) *keyring.Ring[string]
		wantErr error
	}{
		{
			name:    "ring not initialized",
			ring:    func(_ *testing.T) *keyring.Ring[string] { return keyring.New[string]() },
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name: "invalid key length",
			ring: func(t *testing.T) *keyring.Ring[string] {
				return newStringRing(t, map[string]string{testKID: shortKey})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := NewAESGCM(tt.ring(t))
			_, err := svc.Encrypt([]byte("data"), nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAESGCMService_Decrypt_Errors(t *testing.T) {
	t.Parallel()

	baseRing := newStringRing(t, map[string]string{testKID: testKey})
	baseSvc := NewAESGCM(baseRing)
	validToken, err := baseSvc.Encrypt([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("setup encrypt: %v", err)
	}

	// 篡改密文：翻转 token 中 base64 部分的一个字符。
	tamperToken := func(tok string) string {
		b := []byte(tok)
		idx := len(b) - 1
		if b[idx] == 'A' {
			b[idx] = 'B'
		} else {
			b[idx] = 'A'
		}
		return string(b)
	}

	tests := []struct {
		name    string
		ring    *keyring.Ring[string]
		cipher  string
		aad     []byte
		wantErr error
	}{
		{
			name:   "invalid token format",
			ring:   baseRing,
			cipher: "no-dot-separator",
			aad:    []byte("aad"),
		},
		{
			name:    "ring not initialized",
			ring:    keyring.New[string](),
			cipher:  validToken,
			aad:     []byte("aad"),
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name:   "unknown kid",
			ring:   newStringRing(t, map[string]string{testKID: testKey}),
			cipher: "unknown." + validToken[len(testKID)+1:],
			aad:    []byte("aad"),
		},
		{
			name:   "wrong key",
			ring:   newStringRing(t, map[string]string{testKID: testKeyAlt}),
			cipher: validToken,
			aad:    []byte("aad"),
		},
		{
			name:   "wrong aad",
			ring:   newStringRing(t, map[string]string{testKID: testKey}),
			cipher: validToken,
			aad:    []byte("different-aad"),
		},
		{
			name:   "tampered ciphertext",
			ring:   newStringRing(t, map[string]string{testKID: testKey}),
			cipher: tamperToken(validToken),
			aad:    []byte("aad"),
		},
		{
			name:   "non base64 ciphertext",
			ring:   newStringRing(t, map[string]string{testKID: testKey}),
			cipher: testKID + ".!!!not-base64!!!",
			aad:    []byte("aad"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := NewAESGCM(tt.ring)
			_, err := svc.Decrypt(tt.cipher, tt.aad)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAESGCMService_Decrypt_WrongKeyDecodesDifferently(t *testing.T) {
	t.Parallel()

	// 显式验证不同密钥确实改变密文字节，保证 "wrong key" 用例有意义。
	g1 := encryaes.NewGCM(testKey)
	c1, err := g1.EncryptWithAAD([]byte("x"), nil)
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	g2 := encryaes.NewGCM(testKeyAlt)
	if _, err := g2.DecryptWithAAD(c1, nil); err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}
