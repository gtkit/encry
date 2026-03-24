package keyring

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrKeyNotYetValid = errors.New("key is not yet valid")
	ErrKeyExpired     = errors.New("key is expired")
	ErrKeyRevoked     = errors.New("key is revoked")
	ErrKeyNotActive   = errors.New("key is not active for signing")
	ErrKIDNotFound    = errors.New("kid not found")
)

// KeyStatus 描述 kid 生命周期状态.
type KeyStatus string

const (
	StatusActive   KeyStatus = "active"
	StatusRetiring KeyStatus = "retiring"
	StatusRetired  KeyStatus = "retired"
	StatusRevoked  KeyStatus = "revoked"
)

// Metadata 描述一个 kid 的生命周期和用途.
type Metadata struct {
	KID       string    `json:"kid"`
	Algorithm string    `json:"alg,omitzero"`
	Use       string    `json:"use,omitzero"`
	Status    KeyStatus `json:"status,omitzero"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	NotBefore time.Time `json:"not_before,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	Reason    string    `json:"reason,omitzero"`
}

// Record 把密钥内容和 metadata 绑定在一起.
type Record[T any] struct {
	Key      T        `json:"-"`
	Metadata Metadata `json:"metadata"`
}

// Normalize 把 metadata 中缺失的默认值补齐.
func (m Metadata) Normalize(kid, algorithm, use string) Metadata {
	if m.KID == "" {
		m.KID = kid
	}
	if m.Algorithm == "" {
		m.Algorithm = algorithm
	}
	if m.Use == "" {
		m.Use = use
	}
	if m.Status == "" {
		m.Status = StatusActive
	}
	return m
}

// CanSign 判断当前 metadata 是否允许用于签名或加密.
func (m Metadata) CanSign(now time.Time) bool {
	return m.validationError(now, true) == nil
}

// CanVerify 判断当前 metadata 是否允许用于验签或解密.
func (m Metadata) CanVerify(now time.Time) bool {
	return m.validationError(now, false) == nil
}

// ValidateForSign 返回签名或加密场景下的校验结果.
func (m Metadata) ValidateForSign(now time.Time) error {
	return m.validationError(now, true)
}

// ValidateForVerify 返回验签或解密场景下的校验结果.
func (m Metadata) ValidateForVerify(now time.Time) error {
	return m.validationError(now, false)
}

func (m Metadata) validationError(now time.Time, sign bool) error {
	if m.Status == StatusRevoked || (!m.RevokedAt.IsZero() && !now.Before(m.RevokedAt)) {
		return fmt.Errorf("%w: %s", ErrKeyRevoked, m.KID)
	}
	if !m.NotBefore.IsZero() && now.Before(m.NotBefore) {
		return fmt.Errorf("%w: %s", ErrKeyNotYetValid, m.KID)
	}
	if !m.ExpiresAt.IsZero() && !now.Before(m.ExpiresAt) {
		return fmt.Errorf("%w: %s", ErrKeyExpired, m.KID)
	}
	if sign && m.Status != StatusActive {
		return fmt.Errorf("%w: %s (%s)", ErrKeyNotActive, m.KID, m.Status)
	}
	return nil
}

// ActiveRecord 返回当前 active kid 对应且允许签名的记录.
func ActiveRecord[T any](snapshot *Snapshot[Record[T]], now time.Time) (Record[T], error) {
	record, ok := snapshot.Get(snapshot.ActiveKID)
	if !ok {
		var zero Record[T]
		return zero, fmt.Errorf("%w: %s", ErrActiveKIDNotFound, snapshot.ActiveKID)
	}
	if err := record.Metadata.ValidateForSign(now); err != nil {
		var zero Record[T]
		return zero, err
	}
	return record, nil
}

// VerifyRecord 返回指定 kid 对应且允许验签的记录.
func VerifyRecord[T any](snapshot *Snapshot[Record[T]], kid string, now time.Time) (Record[T], error) {
	record, ok := snapshot.Get(kid)
	if !ok {
		var zero Record[T]
		return zero, fmt.Errorf("%w: %s", ErrKIDNotFound, kid)
	}
	if err := record.Metadata.ValidateForVerify(now); err != nil {
		var zero Record[T]
		return zero, err
	}
	return record, nil
}
