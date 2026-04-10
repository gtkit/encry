package hash

import (
	"container/list"
	"hash/fnv"
	"sync"
	"time"
)

// StringFNV32a returns the FNV-32a hash of a string.
func StringFNV32a(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// StringFNV64a returns the FNV-64a hash of a string.
func StringFNV64a(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// BytesFNV32a returns the FNV-32a hash of a byte slice.
func BytesFNV32a(b []byte) uint32 {
	h := fnv.New32a()
	_, _ = h.Write(b)
	return h.Sum32()
}

// BytesFNV64a returns the FNV-64a hash of a byte slice.
func BytesFNV64a(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

const (
	defaultDuplicateTrackerTTL        = time.Hour
	defaultDuplicateTrackerMaxEntries = 10_000
)

// DuplicateTrackerOptions controls the lifecycle of duplicate entries.
type DuplicateTrackerOptions struct {
	TTL        time.Duration
	MaxEntries int
	Now        func() time.Time
}

type duplicateEntry struct {
	expiresAt time.Time
	order     *list.Element
}

// DuplicateTracker tracks duplicate values within a bounded in-memory window.
type DuplicateTracker struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	order      list.List
	entries    map[string]*duplicateEntry
}

// NewDuplicateTracker creates a bounded duplicate tracker.
func NewDuplicateTracker(opts DuplicateTrackerOptions) *DuplicateTracker {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultDuplicateTrackerTTL
	}
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultDuplicateTrackerMaxEntries
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &DuplicateTracker{
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        now,
		entries:    make(map[string]*duplicateEntry, maxEntries),
	}
}

// IsDuplicate reports whether the value is already present in the current window.
func (t *DuplicateTracker) IsDuplicate(element string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	t.pruneExpired(now)

	if entry, ok := t.entries[element]; ok && now.Before(entry.expiresAt) {
		entry.expiresAt = now.Add(t.ttl)
		t.order.MoveToBack(entry.order)
		return true
	}

	t.evictUntilWithinCapacity()

	order := t.order.PushBack(element)
	t.entries[element] = &duplicateEntry{
		expiresAt: now.Add(t.ttl),
		order:     order,
	}
	return false
}

// Reset clears all tracked values.
func (t *DuplicateTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.order.Init()
	clear(t.entries)
}

func (t *DuplicateTracker) pruneExpired(now time.Time) {
	for element := t.order.Front(); element != nil; {
		next := element.Next()
		key, ok := element.Value.(string)
		if !ok {
			t.order.Remove(element)
			element = next
			continue
		}
		entry := t.entries[key]
		if now.Before(entry.expiresAt) {
			break
		}
		t.remove(key, entry)
		element = next
	}
}

func (t *DuplicateTracker) evictUntilWithinCapacity() {
	for len(t.entries) >= t.maxEntries {
		front := t.order.Front()
		if front == nil {
			return
		}
		key, ok := front.Value.(string)
		if !ok {
			t.order.Remove(front)
			continue
		}
		t.remove(key, t.entries[key])
	}
}

func (t *DuplicateTracker) remove(key string, entry *duplicateEntry) {
	t.order.Remove(entry.order)
	delete(t.entries, key)
}

var defaultDuplicateTracker = NewDuplicateTracker(DuplicateTrackerOptions{})

// Deprecated: use DuplicateTracker to avoid process-wide shared duplicate state.
func IsDuplicate(element string) bool {
	return defaultDuplicateTracker.IsDuplicate(element)
}

// Deprecated: use DuplicateTracker.Reset on an instance you own.
func CleanMap() {
	defaultDuplicateTracker.Reset()
}
