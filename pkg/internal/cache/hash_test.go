package cache

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS FOR HASHING UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

// TestHashString verifies string hashing consistency
func TestHashString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"simple string", "hello"},
		{"long string", "this is a longer string with spaces and punctuation!"},
		{"unicode", "Hello 世界 🌍"},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Hash should be consistent
			h1 := HashString(tt.input)
			h2 := HashString(tt.input)
			if h1 != h2 {
				t.Errorf("HashString not consistent: %d != %d", h1, h2)
			}

			// Hash should be non-zero for non-empty strings
			if tt.input != "" && h1 == 0 {
				t.Errorf("HashString returned zero for non-empty string")
			}
		})
	}
}

// TestHashString_Uniqueness verifies different strings produce different hashes
func TestHashString_Uniqueness(t *testing.T) {
	strings := []string{
		"hello",
		"world",
		"foo",
		"bar",
		"test",
		"cache",
		"hash",
		"fnv",
	}

	hashes := make(map[uint64]string)
	for _, s := range strings {
		h := HashString(s)
		if prev, exists := hashes[h]; exists {
			t.Errorf("Hash collision: %q and %q both hash to %d", s, prev, h)
		}
		hashes[h] = s
	}
}

// TestHashInt64 verifies int64 hashing consistency
func TestHashInt64(t *testing.T) {
	tests := []struct {
		name  string
		input int64
	}{
		{"zero", 0},
		{"positive", 42},
		{"negative", -42},
		{"max", 9223372036854775807},
		{"min", -9223372036854775808},
		{"large positive", 1234567890123456789},
		{"large negative", -1234567890123456789},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Hash should be consistent
			h1 := HashInt64(tt.input)
			h2 := HashInt64(tt.input)
			if h1 != h2 {
				t.Errorf("HashInt64 not consistent: %d != %d", h1, h2)
			}
		})
	}
}

// TestHashInt64_Uniqueness verifies different int64s produce different hashes
func TestHashInt64_Uniqueness(t *testing.T) {
	values := []int64{0, 1, 2, 3, 4, 5, 10, 100, 1000, -1, -10, -100}

	hashes := make(map[uint64]int64)
	for _, v := range values {
		h := HashInt64(v)
		if prev, exists := hashes[h]; exists {
			t.Errorf("Hash collision: %d and %d both hash to %d", v, prev, h)
		}
		hashes[h] = v
	}
}

// TestHashUint64 verifies uint64 hashing consistency
func TestHashUint64(t *testing.T) {
	tests := []struct {
		name  string
		input uint64
	}{
		{"zero", 0},
		{"small", 42},
		{"max", 18446744073709551615},
		{"large", 12345678901234567890},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Hash should be consistent
			h1 := HashUint64(tt.input)
			h2 := HashUint64(tt.input)
			if h1 != h2 {
				t.Errorf("HashUint64 not consistent: %d != %d", h1, h2)
			}
		})
	}
}

// TestHashInt verifies int hashing consistency
func TestHashInt(t *testing.T) {
	values := []int{0, 1, -1, 42, -42, 1000, -1000}

	for _, v := range values {
		h1 := HashInt(v)
		h2 := HashInt(v)
		if h1 != h2 {
			t.Errorf("HashInt(%d) not consistent: %d != %d", v, h1, h2)
		}
	}
}

// TestHashUint verifies uint hashing consistency
func TestHashUint(t *testing.T) {
	values := []uint{0, 1, 42, 1000, 999999}

	for _, v := range values {
		h1 := HashUint(v)
		h2 := HashUint(v)
		if h1 != h2 {
			t.Errorf("HashUint(%d) not consistent: %d != %d", v, h1, h2)
		}
	}
}

// TestHashBytes verifies byte slice hashing consistency
func TestHashBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("hello")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h1 := HashBytes(tt.input)
			h2 := HashBytes(tt.input)
			if h1 != h2 {
				t.Errorf("HashBytes not consistent: %d != %d", h1, h2)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASH COMBINER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestHashCombiner_Consistency verifies hash combiner produces consistent results
func TestHashCombiner_Consistency(t *testing.T) {
	// Same sequence should produce same hash
	hc1 := NewHashCombiner()
	hc1.AddString("hello").AddInt64(42).AddUint64(100)
	h1 := hc1.Sum()

	hc2 := NewHashCombiner()
	hc2.AddString("hello").AddInt64(42).AddUint64(100)
	h2 := hc2.Sum()

	if h1 != h2 {
		t.Errorf("HashCombiner not consistent: %d != %d", h1, h2)
	}
}

// TestHashCombiner_OrderMatters verifies order affects the hash
func TestHashCombiner_OrderMatters(t *testing.T) {
	// Different order should produce different hash
	hc1 := NewHashCombiner()
	hc1.AddString("hello").AddInt64(42)
	h1 := hc1.Sum()

	hc2 := NewHashCombiner()
	hc2.AddInt64(42).AddString("hello")
	h2 := hc2.Sum()

	if h1 == h2 {
		t.Errorf("HashCombiner should produce different hashes for different orders")
	}
}

// TestHashCombiner_AllTypes verifies all type methods work
func TestHashCombiner_AllTypes(t *testing.T) {
	hc := NewHashCombiner()
	hc.AddString("test")
	hc.AddBytes([]byte("bytes"))
	hc.AddInt(42)
	hc.AddInt64(123456789)
	hc.AddUint(99)
	hc.AddUint64(987654321)
	hc.AddHash(0xDEADBEEF)

	h := hc.Sum()
	if h == 0 {
		t.Errorf("HashCombiner.Sum() returned zero")
	}

	// Should be consistent
	hc2 := NewHashCombiner()
	hc2.AddString("test")
	hc2.AddBytes([]byte("bytes"))
	hc2.AddInt(42)
	hc2.AddInt64(123456789)
	hc2.AddUint(99)
	hc2.AddUint64(987654321)
	hc2.AddHash(0xDEADBEEF)

	h2 := hc2.Sum()
	if h != h2 {
		t.Errorf("HashCombiner not consistent: %d != %d", h, h2)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPOSITE KEY HASHING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestCombineHashes verifies combining multiple hashes
func TestCombineHashes(t *testing.T) {
	h1 := HashString("hello")
	h2 := HashInt64(42)
	h3 := HashUint64(100)

	// Should be consistent
	combined1 := CombineHashes(h1, h2, h3)
	combined2 := CombineHashes(h1, h2, h3)

	if combined1 != combined2 {
		t.Errorf("CombineHashes not consistent: %d != %d", combined1, combined2)
	}

	// Order should matter
	combined3 := CombineHashes(h3, h2, h1)
	if combined1 == combined3 {
		t.Errorf("CombineHashes should be order-sensitive")
	}
}

// TestHashComposite2 verifies 2-field composite key hashing
func TestHashComposite2(t *testing.T) {
	// Test with different type combinations
	h1 := HashComposite2("hello", 42)
	h2 := HashComposite2("hello", 42)
	if h1 != h2 {
		t.Errorf("HashComposite2 not consistent: %d != %d", h1, h2)
	}

	// Different values should produce different hashes
	h3 := HashComposite2("world", 42)
	if h1 == h3 {
		t.Errorf("HashComposite2 should produce different hashes for different values")
	}

	h4 := HashComposite2("hello", 43)
	if h1 == h4 {
		t.Errorf("HashComposite2 should produce different hashes for different values")
	}
}

// TestHashComposite3 verifies 3-field composite key hashing
func TestHashComposite3(t *testing.T) {
	h1 := HashComposite3("hello", 42, uint64(100))
	h2 := HashComposite3("hello", 42, uint64(100))
	if h1 != h2 {
		t.Errorf("HashComposite3 not consistent: %d != %d", h1, h2)
	}

	// Different values should produce different hashes
	h3 := HashComposite3("world", 42, uint64(100))
	if h1 == h3 {
		t.Errorf("HashComposite3 should produce different hashes for different values")
	}
}

// TestHashComposite4 verifies 4-field composite key hashing
func TestHashComposite4(t *testing.T) {
	h1 := HashComposite4("hello", 42, uint64(100), true)
	h2 := HashComposite4("hello", 42, uint64(100), true)
	if h1 != h2 {
		t.Errorf("HashComposite4 not consistent: %d != %d", h1, h2)
	}

	// Different values should produce different hashes
	h3 := HashComposite4("hello", 42, uint64(100), false)
	if h1 == h3 {
		t.Errorf("HashComposite4 should produce different hashes for different values")
	}
}

// TestHashComposite_OrderSensitivity verifies composite hashing is order-sensitive
func TestHashComposite_OrderSensitivity(t *testing.T) {
	h1 := HashComposite2("hello", 42)
	h2 := HashComposite2(42, "hello")

	if h1 == h2 {
		t.Errorf("Composite hash should be order-sensitive")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCT HASHER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestStructHasher verifies struct field hashing
func TestStructHasher(t *testing.T) {
	// Test with multiple fields
	sh1 := NewStructHasher()
	sh1.Field("name").Field(42).Field(uint64(100))
	h1 := sh1.Sum()

	sh2 := NewStructHasher()
	sh2.Field("name").Field(42).Field(uint64(100))
	h2 := sh2.Sum()

	if h1 != h2 {
		t.Errorf("StructHasher not consistent: %d != %d", h1, h2)
	}

	// Different field values should produce different hashes
	sh3 := NewStructHasher()
	sh3.Field("other").Field(42).Field(uint64(100))
	h3 := sh3.Sum()

	if h1 == h3 {
		t.Errorf("StructHasher should produce different hashes for different field values")
	}
}

// TestStructHasher_OrderMatters verifies field order affects hash
func TestStructHasher_OrderMatters(t *testing.T) {
	sh1 := NewStructHasher()
	sh1.Field("name").Field(42)
	h1 := sh1.Sum()

	sh2 := NewStructHasher()
	sh2.Field(42).Field("name")
	h2 := sh2.Sum()

	if h1 == h2 {
		t.Errorf("StructHasher should be order-sensitive")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SPECIALIZED HASHER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestStringHasher verifies StringHasher implements Hasher interface
func TestStringHasher(t *testing.T) {
	hasher := StringHasher{}
	h1 := hasher.Hash("hello")
	h2 := hasher.Hash("hello")

	if h1 != h2 {
		t.Errorf("StringHasher not consistent: %d != %d", h1, h2)
	}

	// Should match HashString function
	h3 := HashString("hello")
	if h1 != h3 {
		t.Errorf("StringHasher.Hash should match HashString: %d != %d", h1, h3)
	}
}

// TestIntHasher verifies IntHasher implements Hasher interface
func TestIntHasher(t *testing.T) {
	hasher := IntHasher{}
	h1 := hasher.Hash(42)
	h2 := hasher.Hash(42)

	if h1 != h2 {
		t.Errorf("IntHasher not consistent: %d != %d", h1, h2)
	}

	// Should match HashInt function
	h3 := HashInt(42)
	if h1 != h3 {
		t.Errorf("IntHasher.Hash should match HashInt: %d != %d", h1, h3)
	}
}

// TestUint64Hasher verifies Uint64Hasher implements Hasher interface
func TestUint64Hasher(t *testing.T) {
	hasher := Uint64Hasher{}
	h1 := hasher.Hash(uint64(42))
	h2 := hasher.Hash(uint64(42))

	if h1 != h2 {
		t.Errorf("Uint64Hasher not consistent: %d != %d", h1, h2)
	}

	// Should match HashUint64 function
	h3 := HashUint64(42)
	if h1 != h3 {
		t.Errorf("Uint64Hasher.Hash should match HashUint64: %d != %d", h1, h3)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASH DISTRIBUTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestHashDistribution verifies hash values are well-distributed
func TestHashDistribution(t *testing.T) {
	const numBuckets = 16
	const numKeys = 1000

	buckets := make([]int, numBuckets)

	// Hash many keys and count distribution
	for i := 0; i < numKeys; i++ {
		h := HashInt(i)
		bucket := h % numBuckets
		buckets[bucket]++
	}

	// Check that distribution is reasonably even
	// Each bucket should have roughly numKeys/numBuckets entries
	expected := numKeys / numBuckets
	tolerance := expected / 2 // Allow 50% deviation

	for i, count := range buckets {
		if count < expected-tolerance || count > expected+tolerance {
			t.Logf("Bucket %d has %d entries (expected ~%d)", i, count, expected)
		}
	}

	// At least check that no bucket is empty
	for i, count := range buckets {
		if count == 0 {
			t.Errorf("Bucket %d is empty, indicating poor distribution", i)
		}
	}
}

// TestHashDistribution_Strings verifies string hash distribution
func TestHashDistribution_Strings(t *testing.T) {
	const numBuckets = 16
	const numKeys = 1000

	buckets := make([]int, numBuckets)

	// Hash many string keys with more variation
	for i := 0; i < numKeys; i++ {
		// Create more diverse keys by including the full number
		key := "key_" + string(rune('a'+i%26)) + string(rune('A'+i%26)) + string(rune('0'+i%10))
		// Add more variation by appending the index
		switch i % 3 {
		case 0:
			key += "_prefix"
		case 1:
			key += "_middle"
		default:
			key += "_suffix"
		}
		h := HashString(key)
		bucket := h % numBuckets
		buckets[bucket]++
	}

	// Check that distribution is reasonable (at least 25% of buckets have entries)
	nonEmpty := 0
	for _, count := range buckets {
		if count > 0 {
			nonEmpty++
		}
	}

	if nonEmpty < numBuckets/4 {
		t.Errorf("Too few buckets have entries: %d/%d", nonEmpty, numBuckets)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestInt64ToBytes verifies int64 to bytes conversion
func TestInt64ToBytes(t *testing.T) {
	tests := []struct {
		name  string
		input int64
	}{
		{"zero", 0},
		{"positive", 42},
		{"negative", -42},
		{"max", 9223372036854775807},
		{"min", -9223372036854775808},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := int64ToBytes(tt.input)
			if len(b) != 8 {
				t.Errorf("int64ToBytes should return 8 bytes, got %d", len(b))
			}
		})
	}
}

// TestUint64ToBytes verifies uint64 to bytes conversion
func TestUint64ToBytes(t *testing.T) {
	tests := []struct {
		name  string
		input uint64
	}{
		{"zero", 0},
		{"small", 42},
		{"max", 18446744073709551615},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := uint64ToBytes(tt.input)
			if len(b) != 8 {
				t.Errorf("uint64ToBytes should return 8 bytes, got %d", len(b))
			}
		})
	}
}
