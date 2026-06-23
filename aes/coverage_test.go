package aes_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	encaes "github.com/gtkit/encry/aes"
	"github.com/stretchr/testify/require"
)

const (
	validKey16 = "IgkibX71IEf382PT" // 16 字节 -> AES-128
	badKey15   = "IgkibX71IEf382P"  // 15 字节 -> 非法
)

func TestCBCEncryptErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		plainText string
		wantErr   bool
	}{
		{name: "success", key: validKey16, plainText: "hello", wantErr: false},
		{name: "empty plaintext", key: validKey16, plainText: "", wantErr: false},
		{name: "invalid key length", key: badKey15, plainText: "hello", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enc := encaes.NewCBC(tt.key)
			got, err := enc.Encrypt([]byte(tt.plainText))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			dec := encaes.NewCBC(tt.key)
			plain, err := dec.Decrypt(got)
			require.NoError(t, err)
			require.Equal(t, tt.plainText, plain)
		})
	}
}

func TestCBCDecryptErrors(t *testing.T) {
	t.Parallel()

	// 构造一个版本前缀正确但长度不足的 base64（只有版本字节 + 不完整 IV）。
	shortVersioned := base64.URLEncoding.EncodeToString([]byte{1, 0, 0})

	// 构造一个版本正确、IV 完整，但密文长度非块整数倍的数据。
	notBlockAligned := make([]byte, 1+aes.BlockSize+5)
	notBlockAligned[0] = 1
	notBlockAligned = []byte(base64.URLEncoding.EncodeToString(notBlockAligned))

	tests := []struct {
		name    string
		key     string
		input   string
		wantErr bool
	}{
		{name: "invalid base64", key: validKey16, input: "%%%not-base64%%%", wantErr: true},
		{name: "invalid key length", key: badKey15, input: base64.URLEncoding.EncodeToString([]byte{1, 2, 3}), wantErr: true},
		{name: "empty after decode", key: validKey16, input: "", wantErr: true},
		{name: "wrong version byte", key: validKey16, input: base64.URLEncoding.EncodeToString([]byte{9, 9, 9}), wantErr: true},
		{name: "too short for iv", key: validKey16, input: shortVersioned, wantErr: true},
		{name: "ciphertext not block aligned", key: validKey16, input: string(notBlockAligned), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := encaes.NewCBC(tt.key)
			_, err := dec.Decrypt(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestCBCDecryptInvalidPadding 用合法密钥加密但篡改最后一块，触发 PKCS#7 反填充失败。
func TestCBCDecryptInvalidPadding(t *testing.T) {
	t.Parallel()

	key := validKey16
	block, err := aes.NewCipher([]byte(key))
	require.NoError(t, err)

	// 明文为一整块全 0，CBC 加密后反填充会得到非法 padding 值。
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	require.NoError(t, err)

	// 这里直接加密未做 PKCS#7 填充的随机块，使反填充极可能失败。
	plain := make([]byte, aes.BlockSize)
	for i := range plain {
		plain[i] = 0x00 // 最后一字节为 0 -> unPadding==0 -> errInvalidPadding
	}
	encrypted := make([]byte, 1+aes.BlockSize+aes.BlockSize)
	encrypted[0] = 1
	copy(encrypted[1:], iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted[1+aes.BlockSize:], plain)

	dec := encaes.NewCBC(key)
	_, err = dec.Decrypt(base64.URLEncoding.EncodeToString(encrypted))
	require.Error(t, err)
}

func TestCFBErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		text    string
		wantErr bool
	}{
		{name: "success", key: validKey16, text: "hello-cfb", wantErr: false},
		{name: "empty plaintext", key: validKey16, text: "", wantErr: false},
		{name: "invalid key length", key: badKey15, text: "hello", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enc := encaes.NewCFB(tt.key)
			got, err := enc.Encrypt([]byte(tt.text))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			dec := encaes.NewCFB(tt.key)
			plain, err := dec.Decrypt(got)
			require.NoError(t, err)
			require.Equal(t, tt.text, plain)
		})
	}
}

func TestCFBDecryptErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		input   string
		wantErr bool
	}{
		{name: "invalid base64", key: validKey16, input: "%%%not-base64%%%", wantErr: true},
		// 合法 base64 但长度不足，新旧两种路径都失败。
		{name: "too short", key: validKey16, input: base64.URLEncoding.EncodeToString([]byte{1, 2, 3}), wantErr: true},
		// 非法 key：当前路径与 legacy 路径都因 NewCipher 失败。
		{name: "invalid key length", key: badKey15, input: base64.URLEncoding.EncodeToString(make([]byte, 64)), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := encaes.NewCFB(tt.key)
			_, err := dec.Decrypt(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestCFBLegacyDecrypt 构造旧格式密文（无版本前缀、IV 前缀校验），覆盖 decryptLegacyCFB 成功路径。
func TestCFBLegacyDecrypt(t *testing.T) {
	t.Parallel()

	key := validKey16
	ciph, err := aes.NewCipher([]byte(key))
	require.NoError(t, err)

	plain := "legacy-secret"
	// 旧格式：data = IV(BlockSize) + Enc(IV || plain)，解密后校验前 BlockSize 与 IV 相等。
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	require.NoError(t, err)
	// 确保 IV 首字节不等于版本号，避免误入新格式分支后回退；即便走新格式失败也会回退到 legacy。
	iv[0] = 0xFE

	payload := make([]byte, aes.BlockSize+len(plain))
	copy(payload, iv)
	copy(payload[aes.BlockSize:], plain)

	enc := make([]byte, aes.BlockSize+len(payload))
	copy(enc, iv)
	cipher.NewCFBEncrypter(ciph, iv).XORKeyStream(enc[aes.BlockSize:], payload) //nolint:staticcheck // 构造旧格式密文用于回归

	dec := encaes.NewCFB(key)
	got, err := dec.Decrypt(base64.URLEncoding.EncodeToString(enc))
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

// TestCFBLegacyDecryptMismatch 构造 IV 校验不通过的旧格式密文，覆盖 legacy 校验失败分支。
func TestCFBLegacyDecryptMismatch(t *testing.T) {
	t.Parallel()

	key := validKey16
	// 长度 >= BlockSize 但内容随机，IV 前缀校验几乎必然失败，触发 ErrDecryptFailed。
	raw := make([]byte, aes.BlockSize*3)
	_, err := io.ReadFull(rand.Reader, raw)
	require.NoError(t, err)
	raw[0] = 0x00 // 避免命中版本前缀的新格式分支

	dec := encaes.NewCFB(key)
	_, err = dec.Decrypt(base64.URLEncoding.EncodeToString(raw))
	require.Error(t, err)
}

func TestGCMErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		plainText string
		wantErr   bool
	}{
		{name: "success", key: validKey16, plainText: "hello-gcm", wantErr: false},
		{name: "empty plaintext", key: validKey16, plainText: "", wantErr: false},
		{name: "invalid key length", key: badKey15, plainText: "hello", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := encaes.NewGCM(tt.key)
			got, err := g.Encrypt([]byte(tt.plainText))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			plain, err := g.Decrypt(got)
			require.NoError(t, err)
			require.Equal(t, tt.plainText, plain)
		})
	}
}

func TestGCMDecryptErrors(t *testing.T) {
	t.Parallel()

	valid := encaes.NewGCM(validKey16)
	good, err := valid.Encrypt([]byte("payload"))
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     string
		input   string
		wantErr bool
	}{
		{name: "invalid base64", key: validKey16, input: "%%%not-base64%%%", wantErr: true},
		{name: "invalid key length", key: badKey15, input: good, wantErr: true},
		{name: "too short / wrong version", key: validKey16, input: base64.StdEncoding.EncodeToString([]byte{9}), wantErr: true},
		{name: "tampered ciphertext", key: validKey16, input: base64.StdEncoding.EncodeToString(make([]byte, 1+12+16)), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := encaes.NewGCM(tt.key)
			_, err := g.Decrypt(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGCMDecryptWithAADErrors(t *testing.T) {
	t.Parallel()

	g := encaes.NewGCM(validKey16)
	cipherText, err := g.EncryptWithAAD([]byte("msg"), []byte("aad"))
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     string
		input   string
		aad     []byte
		wantErr bool
	}{
		{name: "success with aad", key: validKey16, input: cipherText, aad: []byte("aad"), wantErr: false},
		{name: "wrong aad", key: validKey16, input: cipherText, aad: []byte("nope"), wantErr: true},
		{name: "invalid base64", key: validKey16, input: "%%%", aad: []byte("aad"), wantErr: true},
		{name: "invalid key length", key: badKey15, input: cipherText, aad: []byte("aad"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dec := encaes.NewGCM(tt.key)
			got, err := dec.DecryptWithAAD(tt.input, tt.aad)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte("msg"), got)
		})
	}
}

func TestGCMEncryptWithAADInvalidKey(t *testing.T) {
	t.Parallel()
	g := encaes.NewGCM(badKey15)
	_, err := g.EncryptWithAAD([]byte("msg"), []byte("aad"))
	require.Error(t, err)
}
