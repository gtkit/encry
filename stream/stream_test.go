package stream_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/gtkit/encry/stream"
	"github.com/stretchr/testify/require"
)

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestEncryptWriterError(t *testing.T) {
	key := key32(t)
	// dst 写入即失败：覆盖写 streamID / sealChunk 的错误分支。
	require.Error(t, stream.EncryptStream(key, errWriter{}, bytes.NewReader([]byte("data"))))
}

func TestEncryptReaderError(t *testing.T) {
	key := key32(t)
	var out bytes.Buffer
	require.Error(t, stream.EncryptStream(key, &out, errReader{}))
}

func TestDecryptReaderError(t *testing.T) {
	key := key32(t)
	var out bytes.Buffer
	// 先写出合法 streamID 头，再让后续读取失败。
	header := make([]byte, 19)
	require.Error(t, stream.DecryptStream(key, &out, io.MultiReader(bytes.NewReader(header), errReader{})))
}

func ExampleEncryptStream() {
	key := make([]byte, stream.KeySize) // 演示用全零 key；实际应使用随机密钥
	var cipherBuf bytes.Buffer
	if err := stream.EncryptStream(key, &cipherBuf, bytes.NewReader([]byte("large file content"))); err != nil {
		panic(err)
	}

	var plainBuf bytes.Buffer
	if err := stream.DecryptStream(key, &plainBuf, &cipherBuf); err != nil {
		panic(err)
	}
	fmt.Println(plainBuf.String())
	// Output: large file content
}

func key32(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, stream.KeySize)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func encrypt(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, stream.EncryptStream(key, &out, bytes.NewReader(plain)))
	return out.Bytes()
}

func TestRoundTripSizes(t *testing.T) {
	key := key32(t)

	const chunk = 64 * 1024
	sizes := []int{0, 1, 100, chunk - 1, chunk, chunk + 1, 2 * chunk, 3*chunk + 123}

	for _, size := range sizes {
		plain := make([]byte, size)
		_, err := rand.Read(plain)
		require.NoError(t, err)

		ct := encrypt(t, key, plain)

		var dec bytes.Buffer
		require.NoError(t, stream.DecryptStream(key, &dec, bytes.NewReader(ct)))
		require.True(t, bytes.Equal(plain, dec.Bytes()), "size=%d", size)
	}
}

func TestInvalidKeySize(t *testing.T) {
	var out bytes.Buffer
	require.ErrorIs(t, stream.EncryptStream([]byte("short"), &out, bytes.NewReader([]byte("x"))), stream.ErrInvalidKeySize)
	require.ErrorIs(t, stream.DecryptStream([]byte("short"), &out, bytes.NewReader([]byte("x"))), stream.ErrInvalidKeySize)
}

func TestWrongKeyFails(t *testing.T) {
	ct := encrypt(t, key32(t), []byte("secret payload"))
	var dec bytes.Buffer
	require.Error(t, stream.DecryptStream(key32(t), &dec, bytes.NewReader(ct)))
}

func TestTamperFails(t *testing.T) {
	key := key32(t)
	ct := encrypt(t, key, []byte("secret payload that is tampered"))

	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xff // 翻转最后一字节（tag）

	var dec bytes.Buffer
	require.Error(t, stream.DecryptStream(key, &dec, bytes.NewReader(tampered)))
}

func TestTruncateLastChunkFails(t *testing.T) {
	key := key32(t)
	const chunk = 64 * 1024
	plain := make([]byte, 2*chunk) // 两个满块
	_, err := rand.Read(plain)
	require.NoError(t, err)

	ct := encrypt(t, key, plain)
	encChunk := chunk + 16
	// 删除最后一个完整密文块（保留 streamID + 第一块）。
	truncated := ct[:len(ct)-encChunk]

	var dec bytes.Buffer
	require.Error(t, stream.DecryptStream(key, &dec, bytes.NewReader(truncated)))
}

func TestDecryptInvalidStream(t *testing.T) {
	key := key32(t)
	// 短于 streamID 头。
	var dec bytes.Buffer
	require.ErrorIs(t, stream.DecryptStream(key, &dec, bytes.NewReader([]byte("short"))), stream.ErrInvalidStream)

	// 仅有 streamID，无任何密文块。
	dec.Reset()
	header := make([]byte, 19)
	require.ErrorIs(t, stream.DecryptStream(key, &dec, bytes.NewReader(header)), stream.ErrInvalidStream)
}
