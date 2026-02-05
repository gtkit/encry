package hash

import (
	"hash/fnv"
)

// StringFNV32a returns the FNV-32a hash of a string.
func StringFNV32a(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// StringFNV64a returns the FNV-64a hash of a string.
func StringFNV64a(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// BytesFNV32a returns the FNV-32a hash of a byte slice.
func BytesFNV32a(b []byte) uint32 {
	h := fnv.New32a()
	h.Write(b)
	return h.Sum32()
}

// BytesFNV64a returns the FNV-64a hash of a byte slice.
func BytesFNV64a(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

var elementsMap = make(map[uint32]struct{}) // 用于存储哈希值的map
func IsDuplicate(element string) bool {
	hash := StringFNV32a(element) // 获取哈希值
	
	// 使用map来跟踪已见过的元素
	if _, exists := elementsMap[hash]; exists {
		return true
	}
	elementsMap[hash] = struct{}{} // 记录哈希值到map中
	return false
}

func exampleIsDuplicate() {
	elements := []string{"apple", "banana", "apple", "orange", "banana"}
	uniqueElements := []string{}
	
	for _, elem := range elements {
		if !IsDuplicate(elem) { // 如果不是重复项，则添加到uniqueElements切片中
			uniqueElements = append(uniqueElements, elem)
		}
	}
	
	// fmt.Println("Unique elements:", uniqueElements) // 输出: [apple banana orange]
}
