package keyring

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
)

var (
	ErrEmptyKeySet        = errors.New("key set is empty")
	ErrActiveKIDNotFound  = errors.New("active kid not found")
	ErrRingNotInitialized = errors.New("key ring not initialized")
)

// Snapshot 是某一时刻的只读密钥视图.
type Snapshot[T any] struct {
	ActiveKID string
	Keys      map[string]T
}

// Active 返回当前生效 kid 对应的密钥.
func (s *Snapshot[T]) Active() (T, error) {
	key, ok := s.Get(s.ActiveKID)
	if !ok {
		var zero T
		return zero, fmt.Errorf("%w: %s", ErrActiveKIDNotFound, s.ActiveKID)
	}
	return key, nil
}

// Get 返回指定 kid 的密钥.
func (s *Snapshot[T]) Get(kid string) (T, bool) {
	key, ok := s.Keys[kid]
	return key, ok
}

// KIDs 返回当前快照中的全部 kid，按字典序排序.
func (s *Snapshot[T]) KIDs() []string {
	return slices.Sorted(maps.Keys(s.Keys))
}

// Ring 提供基于 atomic pointer 的 kid 快照切换.
type Ring[T any] struct {
	state atomic.Pointer[Snapshot[T]]
}

// New 创建一个新的密钥环.
func New[T any]() *Ring[T] {
	return &Ring[T]{}
}

// Store 替换当前密钥快照.
func (r *Ring[T]) Store(activeKID string, keys map[string]T) error {
	if len(keys) == 0 {
		return ErrEmptyKeySet
	}
	if _, ok := keys[activeKID]; !ok {
		return fmt.Errorf("%w: %s", ErrActiveKIDNotFound, activeKID)
	}

	r.state.Store(&Snapshot[T]{
		ActiveKID: activeKID,
		Keys:      maps.Clone(keys),
	})
	return nil
}

// Current 返回当前密钥快照.
func (r *Ring[T]) Current() (*Snapshot[T], error) {
	state := r.state.Load()
	if state == nil {
		return nil, ErrRingNotInitialized
	}
	return state, nil
}
