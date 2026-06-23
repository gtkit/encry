// Package stream 提供基于 io.Reader/io.Writer 的流式认证加密，适合大文件。
//
// 采用 STREAM 构造（XChaCha20-Poly1305）：明文按 64KiB 分块，每块独立 AEAD 加密；
// 每块 nonce = 随机 streamID(19B) || 块计数器(uint32 大端,4B) || 末块标志(1B)，共 24B。
// 计数器与末块标志使解密能检测密文被篡改、截断（缺末块）或丢块/重排。
package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize 是密钥字节长度（32）。
	KeySize = chacha20poly1305.KeySize

	chunkSize   = 64 * 1024 // 明文分块大小
	streamIDLen = 19        // nonce 中的随机前缀长度：19 + 4(counter) + 1(last) = 24
)

var (
	// ErrInvalidKeySize 表示 key 长度不等于 32 字节。
	ErrInvalidKeySize = errors.New("stream: key must be 32 bytes")
	// ErrInvalidStream 表示密文头损坏或长度非法。
	ErrInvalidStream = errors.New("stream: invalid or truncated stream")
	// ErrStreamTooLong 表示分块数超过 uint32 计数器上限（约 256TiB），
	// 继续将导致 nonce 计数器回绕、复用，故中止以避免破坏安全性。
	ErrStreamTooLong = errors.New("stream: input exceeds maximum chunk count")
)

func makeNonce(streamID []byte, counter uint32, last bool) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24
	copy(nonce, streamID)
	binary.BigEndian.PutUint32(nonce[streamIDLen:streamIDLen+4], counter)
	if last {
		nonce[streamIDLen+4] = 1
	}
	return nonce
}

// EncryptStream 从 src 读取明文，分块认证加密后写入 dst。
func EncryptStream(key []byte, dst io.Writer, src io.Reader) error {
	if len(key) != KeySize {
		return ErrInvalidKeySize
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	streamID := make([]byte, streamIDLen)
	if _, err := rand.Read(streamID); err != nil {
		return err
	}
	if _, err := dst.Write(streamID); err != nil {
		return err
	}

	bufA := make([]byte, chunkSize)
	bufB := make([]byte, chunkSize)
	var counter uint32

	// 读取第一块。
	prev, prevErr := readChunk(src, bufA)
	if prevErr != nil && !errors.Is(prevErr, io.EOF) && !errors.Is(prevErr, io.ErrUnexpectedEOF) {
		return prevErr
	}
	// 空输入 / 单块（部分或恰好读到 EOF）时直接作为末块输出。
	if errors.Is(prevErr, io.EOF) || errors.Is(prevErr, io.ErrUnexpectedEOF) {
		return sealChunk(aead, dst, makeNonce(streamID, counter, true), prev)
	}

	for {
		cur, curErr := readChunk(src, bufB)
		if curErr != nil && !errors.Is(curErr, io.EOF) && !errors.Is(curErr, io.ErrUnexpectedEOF) {
			return curErr
		}
		if errors.Is(curErr, io.EOF) {
			// 没有更多数据：prev 即末块（一个恰好填满的末块）。
			return sealChunk(aead, dst, makeNonce(streamID, counter, true), prev)
		}
		// prev 不是末块。
		if err := sealChunk(aead, dst, makeNonce(streamID, counter, false), prev); err != nil {
			return err
		}
		if counter == math.MaxUint32 {
			return ErrStreamTooLong
		}
		counter++
		if errors.Is(curErr, io.ErrUnexpectedEOF) {
			// cur 是部分块，即末块。
			return sealChunk(aead, dst, makeNonce(streamID, counter, true), cur)
		}
		// cur 是满块，交换缓冲继续。
		prev, bufA, bufB = cur, bufB, bufA
	}
}

// DecryptStream 从 src 读取密文，校验解密后写入 dst。
func DecryptStream(key []byte, dst io.Writer, src io.Reader) error {
	if len(key) != KeySize {
		return ErrInvalidKeySize
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	streamID := make([]byte, streamIDLen)
	if _, err := io.ReadFull(src, streamID); err != nil {
		return ErrInvalidStream
	}

	encChunkSize := chunkSize + aead.Overhead()
	bufA := make([]byte, encChunkSize)
	bufB := make([]byte, encChunkSize)
	var counter uint32

	prev, prevErr := readChunk(src, bufA)
	if prevErr != nil && !errors.Is(prevErr, io.EOF) && !errors.Is(prevErr, io.ErrUnexpectedEOF) {
		return prevErr
	}
	if errors.Is(prevErr, io.EOF) && len(prev) == 0 {
		// 没有任何密文块（连空末块都没有）→ 非法。
		return ErrInvalidStream
	}
	if errors.Is(prevErr, io.EOF) || errors.Is(prevErr, io.ErrUnexpectedEOF) {
		return openChunk(aead, dst, makeNonce(streamID, counter, true), prev)
	}

	for {
		cur, curErr := readChunk(src, bufB)
		if curErr != nil && !errors.Is(curErr, io.EOF) && !errors.Is(curErr, io.ErrUnexpectedEOF) {
			return curErr
		}
		if errors.Is(curErr, io.EOF) {
			return openChunk(aead, dst, makeNonce(streamID, counter, true), prev)
		}
		if err := openChunk(aead, dst, makeNonce(streamID, counter, false), prev); err != nil {
			return err
		}
		if counter == math.MaxUint32 {
			return ErrStreamTooLong
		}
		counter++
		if errors.Is(curErr, io.ErrUnexpectedEOF) {
			return openChunk(aead, dst, makeNonce(streamID, counter, true), cur)
		}
		prev, bufA, bufB = cur, bufB, bufA
	}
}

// readChunk 用 io.ReadFull 读满 buf；返回读取到的切片与 ReadFull 的错误状态
// （nil=满块；io.ErrUnexpectedEOF=部分块；io.EOF=无数据）。
func readChunk(src io.Reader, buf []byte) ([]byte, error) {
	n, err := io.ReadFull(src, buf)
	return buf[:n], err
}

func sealChunk(aead cipher.AEAD, dst io.Writer, nonce, plain []byte) error {
	ct := aead.Seal(nil, nonce, plain, nil)
	_, err := dst.Write(ct)
	return err
}

func openChunk(aead cipher.AEAD, dst io.Writer, nonce, ct []byte) error {
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	_, err = dst.Write(pt)
	return err
}
