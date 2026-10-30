package cache

import (
	"fmt"
	"hash/fnv"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FNV-1a HASHING UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════
//
// FNV-1a (Fowler-Noll-Vo) is a fast, non-cryptographic hash function with good
// distribution properties. It's ideal for hash tables and caching.
//
// Features:
//   • Fast computation (simple XOR and multiply operations)
//   • Good avalanche effect (small input changes → large hash changes)
//   • Low collision rate for typical data
//   • Deterministic and consistent across runs
//
// This file provides:
//   • Specialized hashers for common key types (string, int, uint64)
//   • Composite key hashing with proper combining
//   • Struct field hashing utilities
// ═══════════════════════════════════════════════════════════════════════════════

// FNV-1a constants (64-bit)
const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// ═══════════════════════════════════════════════════════════════════════════════
// SPECIALIZED HASHERS FOR COMMON TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// StringHasher implements FNV-1a hashing for string keys
type StringHasher struct{}

func (h StringHasher) Hash(key string) uint64 {
	return HashString(key)
}

// IntHasher implements FNV-1a hashing for int keys
type IntHasher struct{}

func (h IntHasher) Hash(key int) uint64 {
	return HashInt64(int64(key))
}

// Uint64Hasher implements FNV-1a hashing for uint64 keys
type Uint64Hasher struct{}

func (h Uint64Hasher) Hash(key uint64) uint64 {
	return HashUint64(key)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE HASHING FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// HashString computes FNV-1a hash for a string
func HashString(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// HashBytes computes FNV-1a hash for a byte slice
func HashBytes(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// HashInt64 computes FNV-1a hash for an int64
func HashInt64(n int64) uint64 {
	h := uint64(fnvOffset64)
	b := int64ToBytes(n)
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

// HashUint64 computes FNV-1a hash for a uint64
func HashUint64(n uint64) uint64 {
	h := uint64(fnvOffset64)
	b := uint64ToBytes(n)
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

// HashInt computes FNV-1a hash for an int
func HashInt(n int) uint64 {
	return HashInt64(int64(n))
}

// HashUint computes FNV-1a hash for a uint
func HashUint(n uint) uint64 {
	return HashUint64(uint64(n))
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPOSITE KEY HASHING
// ═══════════════════════════════════════════════════════════════════════════════

// HashCombiner provides utilities for combining multiple hash values
type HashCombiner struct {
	hash uint64
}

// NewHashCombiner creates a new hash combiner
func NewHashCombiner() *HashCombiner {
	return &HashCombiner{hash: fnvOffset64}
}

// AddString adds a string to the combined hash
func (hc *HashCombiner) AddString(s string) *HashCombiner {
	for i := 0; i < len(s); i++ {
		hc.hash ^= uint64(s[i])
		hc.hash *= fnvPrime64
	}
	return hc
}

// AddBytes adds a byte slice to the combined hash
func (hc *HashCombiner) AddBytes(b []byte) *HashCombiner {
	for _, c := range b {
		hc.hash ^= uint64(c)
		hc.hash *= fnvPrime64
	}
	return hc
}

// AddInt64 adds an int64 to the combined hash
func (hc *HashCombiner) AddInt64(n int64) *HashCombiner {
	b := int64ToBytes(n)
	return hc.AddBytes(b)
}

// AddUint64 adds a uint64 to the combined hash
func (hc *HashCombiner) AddUint64(n uint64) *HashCombiner {
	b := uint64ToBytes(n)
	return hc.AddBytes(b)
}

// AddInt adds an int to the combined hash
func (hc *HashCombiner) AddInt(n int) *HashCombiner {
	return hc.AddInt64(int64(n))
}

// AddUint adds a uint to the combined hash
func (hc *HashCombiner) AddUint(n uint) *HashCombiner {
	return hc.AddUint64(uint64(n))
}

// AddHash adds another hash value to the combined hash
func (hc *HashCombiner) AddHash(h uint64) *HashCombiner {
	return hc.AddUint64(h)
}

// Sum returns the final combined hash value
func (hc *HashCombiner) Sum() uint64 {
	return hc.hash
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS FOR COMPOSITE KEYS
// ═══════════════════════════════════════════════════════════════════════════════

// CombineHashes combines multiple hash values into a single hash
func CombineHashes(hashes ...uint64) uint64 {
	hc := NewHashCombiner()
	for _, h := range hashes {
		hc.AddHash(h)
	}
	return hc.Sum()
}

// HashComposite2 hashes a 2-field composite key
func HashComposite2[T1, T2 any](v1 T1, v2 T2) uint64 {
	hc := NewHashCombiner()
	hashValue(hc, v1)
	hashValue(hc, v2)
	return hc.Sum()
}

// HashComposite3 hashes a 3-field composite key
func HashComposite3[T1, T2, T3 any](v1 T1, v2 T2, v3 T3) uint64 {
	hc := NewHashCombiner()
	hashValue(hc, v1)
	hashValue(hc, v2)
	hashValue(hc, v3)
	return hc.Sum()
}

// HashComposite4 hashes a 4-field composite key
func HashComposite4[T1, T2, T3, T4 any](v1 T1, v2 T2, v3 T3, v4 T4) uint64 {
	hc := NewHashCombiner()
	hashValue(hc, v1)
	hashValue(hc, v2)
	hashValue(hc, v3)
	hashValue(hc, v4)
	return hc.Sum()
}

// hashValue adds a value of any type to the hash combiner
func hashValue(hc *HashCombiner, v any) {
	switch val := v.(type) {
	case string:
		hc.AddString(val)
	case []byte:
		hc.AddBytes(val)
	case int:
		hc.AddInt(val)
	case int64:
		hc.AddInt64(val)
	case int32:
		hc.AddInt64(int64(val))
	case int16:
		hc.AddInt64(int64(val))
	case int8:
		hc.AddInt64(int64(val))
	case uint:
		hc.AddUint(val)
	case uint64:
		hc.AddUint64(val)
	case uint32:
		hc.AddUint64(uint64(val))
	case uint16:
		hc.AddUint64(uint64(val))
	case uint8:
		hc.AddUint64(uint64(val))
	case bool:
		if val {
			hc.AddUint64(1)
		} else {
			hc.AddUint64(0)
		}
	default:
		// For other types, use reflection-free approach
		// Hash the memory representation (works for structs)
		hashAny(hc, v)
	}
}

// hashAny hashes arbitrary values using their string representation
func hashAny(hc *HashCombiner, v any) {
	s := fmt.Sprintf("%v", v)
	hc.AddString(s)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCT FIELD HASHING UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

// StructHasher provides a builder pattern for hashing struct fields
type StructHasher struct {
	combiner *HashCombiner
}

// NewStructHasher creates a new struct hasher
func NewStructHasher() *StructHasher {
	return &StructHasher{
		combiner: NewHashCombiner(),
	}
}

// Field adds a field value to the struct hash
func (sh *StructHasher) Field(v any) *StructHasher {
	hashValue(sh.combiner, v)
	return sh
}

// Sum returns the final hash value for the struct
func (sh *StructHasher) Sum() uint64 {
	return sh.combiner.Sum()
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (moved from cache.go for reuse)
// ═══════════════════════════════════════════════════════════════════════════════

// int64ToBytes converts an int64 to a byte slice (little-endian)
func int64ToBytes(n int64) []byte {
	b := make([]byte, 8)
	b[0] = byte(n)
	b[1] = byte(n >> 8)
	b[2] = byte(n >> 16)
	b[3] = byte(n >> 24)
	b[4] = byte(n >> 32)
	b[5] = byte(n >> 40)
	b[6] = byte(n >> 48)
	b[7] = byte(n >> 56)
	return b
}

// uint64ToBytes converts a uint64 to a byte slice (little-endian)
func uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(n)
	b[1] = byte(n >> 8)
	b[2] = byte(n >> 16)
	b[3] = byte(n >> 24)
	b[4] = byte(n >> 32)
	b[5] = byte(n >> 40)
	b[6] = byte(n >> 48)
	b[7] = byte(n >> 56)
	return b
}
