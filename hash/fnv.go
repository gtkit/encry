package hash

import (
	"hash/fnv"
	"sync"
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

var duplicateTracker = struct {
	mu       sync.Mutex
	elements map[string]struct{}
}{
	elements: make(map[string]struct{}),
}

func IsDuplicate(element string) bool {
	duplicateTracker.mu.Lock()
	defer duplicateTracker.mu.Unlock()

	if _, exists := duplicateTracker.elements[element]; exists {
		return true
	}
	duplicateTracker.elements[element] = struct{}{}
	return false
}

func CleanMap() {
	duplicateTracker.mu.Lock()
	defer duplicateTracker.mu.Unlock()

	clear(duplicateTracker.elements)
}
