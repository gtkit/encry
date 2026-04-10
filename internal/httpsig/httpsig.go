package httpsig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HeaderSignature = "X-Signature"
	HeaderTimestamp = "X-Signature-Timestamp"
	HeaderNonce     = "X-Signature-Nonce"
)

var (
	ErrMissingSignature = errors.New("missing signature")
	ErrMissingTimestamp = errors.New("missing signature timestamp")
	ErrMissingNonce     = errors.New("missing signature nonce")
	ErrInvalidTimestamp = errors.New("invalid signature timestamp")
	ErrTimestampSkew    = errors.New("signature timestamp outside allowed skew")
	ErrReplayDetected   = errors.New("replay detected")
	ErrSignatureInvalid = errors.New("signature verification failed")
)

// Signer 负责对 canonical payload 签名.
type Signer interface {
	Sign(payload []byte) (string, error)
}

// Verifier 负责对 canonical payload 验签.
type Verifier interface {
	Verify(payload []byte, signed string) (bool, error)
}

// NonceStore 负责记录 timestamp + nonce 组合，防止重放.
type NonceStore interface {
	Use(key string, expiresAt time.Time) (bool, error)
}

// Headers 是请求签名协议用到的头集合.
type Headers struct {
	Signature string
	Timestamp string
	Nonce     string
}

// VerifyOptions 控制验签窗口和防重放策略.
type VerifyOptions struct {
	Now          func() time.Time
	MaxSkew      time.Duration
	Nonces       NonceStore
	MaxBodyBytes int64
}

// MemoryNonceStore 是一个简单的内存防重放实现，适合单进程示例和轻量服务.
type MemoryNonceStore struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// NewMemoryNonceStore 创建一个新的内存 nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{
		items: make(map[string]time.Time),
	}
}

// Use 尝试使用一个 nonce key，若已存在且未过期则视为重放.
func (s *MemoryNonceStore) Use(key string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for nonceKey, deadline := range s.items {
		if !now.Before(deadline) {
			delete(s.items, nonceKey)
		}
	}

	if deadline, ok := s.items[key]; ok && now.Before(deadline) {
		return false, nil
	}
	s.items[key] = expiresAt
	return true, nil
}

// Apply 把签名头写入 http.Header.
func (h Headers) Apply(dst http.Header) {
	dst.Set(HeaderSignature, h.Signature)
	dst.Set(HeaderTimestamp, h.Timestamp)
	dst.Set(HeaderNonce, h.Nonce)
}

// FromHTTP 从 http.Header 中提取签名头.
func FromHTTP(header http.Header) Headers {
	return Headers{
		Signature: header.Get(HeaderSignature),
		Timestamp: header.Get(HeaderTimestamp),
		Nonce:     header.Get(HeaderNonce),
	}
}

// SignRequest 为给定请求要素生成一组签名头.
func SignRequest(signer Signer, method, path, query string, body []byte, at time.Time, nonce string) (Headers, error) {
	timestamp := strconv.FormatInt(at.Unix(), 10)
	payload := CanonicalPayload(method, path, query, body, timestamp, nonce)
	signature, err := signer.Sign(payload)
	if err != nil {
		return Headers{}, err
	}
	return Headers{
		Signature: signature,
		Timestamp: timestamp,
		Nonce:     nonce,
	}, nil
}

// VerifyRequest 根据 canonical request 对签名头进行校验.
func VerifyRequest(verifier Verifier, method, path, query string, body []byte, headers Headers, opts VerifyOptions) error {
	if headers.Signature == "" {
		return ErrMissingSignature
	}
	if headers.Timestamp == "" {
		return ErrMissingTimestamp
	}
	if headers.Nonce == "" {
		return ErrMissingNonce
	}

	requestTime, err := parseTimestamp(headers.Timestamp)
	if err != nil {
		return err
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	maxSkew := opts.MaxSkew
	if maxSkew == 0 {
		maxSkew = 5 * time.Minute
	}

	current := now()
	if delta := current.Sub(requestTime); delta > maxSkew || delta < -maxSkew {
		return ErrTimestampSkew
	}

	payload := CanonicalPayload(method, path, query, body, headers.Timestamp, headers.Nonce)
	ok, err := verifier.Verify(payload, headers.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSignatureInvalid
	}

	if opts.Nonces != nil {
		expiresAt := requestTime.Add(maxSkew)
		ok, err := opts.Nonces.Use(replayKey(headers), expiresAt)
		if err != nil {
			return err
		}
		if !ok {
			return ErrReplayDetected
		}
	}
	return nil
}

// CanonicalPayload 构造规范化签名串.
func CanonicalPayload(method, path, query string, body []byte, timestamp, nonce string) []byte {
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{
		strings.ToUpper(method),
		path,
		query,
		timestamp,
		nonce,
		BodyDigestHex(body),
	}, "\n")
	return []byte(canonical)
}

// BodyDigestHex 计算 body 的 SHA256 十六进制摘要.
func BodyDigestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func parseTimestamp(raw string) (time.Time, error) {
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, ErrInvalidTimestamp
	}
	return time.Unix(seconds, 0), nil
}

func replayKey(headers Headers) string {
	kid, _, _ := strings.Cut(headers.Signature, ".")
	return kid + ":" + headers.Timestamp + ":" + headers.Nonce
}
