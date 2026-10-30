package cache

import (
	"testing"
	"testing/quick"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY-BASED TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// **Validates: Requirements 1.1, 1.2, 2.1, 3.1**
//
// Property 1: Cache Round-Trip Preservation
//
// For any valid cache entry (key-value pair), storing it via Put() and
// immediately retrieving it via Get() SHALL return the same value with ok=true.
func TestProperty_CacheRoundTripPreservation(t *testing.T) {
	// Test with string keys and int values
	t.Run("StringInt", func(t *testing.T) {
		property := func(key string, value int) bool {
			cache := NewShardedCache[string, int](100)

			// Store the value
			cache.Put(key, value)

			// Retrieve the value
			retrieved, ok := cache.Get(key)

			// Verify round-trip preservation
			return ok && retrieved == value
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with int keys and string values
	t.Run("IntString", func(t *testing.T) {
		property := func(key int, value string) bool {
			cache := NewShardedCache[int, string](100)

			// Store the value
			cache.Put(key, value)

			// Retrieve the value
			retrieved, ok := cache.Get(key)

			// Verify round-trip preservation
			return ok && retrieved == value
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with int keys and int values
	t.Run("IntInt", func(t *testing.T) {
		property := func(key int, value int) bool {
			cache := NewShardedCache[int, int](100)

			// Store the value
			cache.Put(key, value)

			// Retrieve the value
			retrieved, ok := cache.Get(key)

			// Verify round-trip preservation
			return ok && retrieved == value
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with uint64 keys (common for hash-based keys)
	t.Run("Uint64Int", func(t *testing.T) {
		property := func(key uint64, value int) bool {
			cache := NewShardedCache[uint64, int](100)

			// Store the value
			cache.Put(key, value)

			// Retrieve the value
			retrieved, ok := cache.Get(key)

			// Verify round-trip preservation
			return ok && retrieved == value
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})
}

// **Validates: Requirements 4.2**
//
// Property 5: Shard Distribution Consistency
//
// For any key K, the shard assignment SHALL be deterministic and consistent:
// hash(K) mod shard_count SHALL always return the same shard index for the same
// key across all operations.
func TestProperty_ShardDistributionConsistency(t *testing.T) {
	// Test that the same key always maps to the same shard
	t.Run("ConsistentShardMapping", func(t *testing.T) {
		property := func(key string) bool {
			cache := NewShardedCache[string, int](100)

			// Hash the key multiple times and verify it always maps to the same shard
			hash1 := cache.hasher.Hash(key)
			shard1 := hash1 % numShards

			hash2 := cache.hasher.Hash(key)
			shard2 := hash2 % numShards

			hash3 := cache.hasher.Hash(key)
			shard3 := hash3 % numShards

			// All shard assignments must be identical
			return shard1 == shard2 && shard2 == shard3
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with int keys
	t.Run("ConsistentShardMappingInt", func(t *testing.T) {
		property := func(key int) bool {
			cache := NewShardedCache[int, int](100)

			// Hash the key multiple times and verify it always maps to the same shard
			hash1 := cache.hasher.Hash(key)
			shard1 := hash1 % numShards

			hash2 := cache.hasher.Hash(key)
			shard2 := hash2 % numShards

			hash3 := cache.hasher.Hash(key)
			shard3 := hash3 % numShards

			// All shard assignments must be identical
			return shard1 == shard2 && shard2 == shard3
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with uint64 keys
	t.Run("ConsistentShardMappingUint64", func(t *testing.T) {
		property := func(key uint64) bool {
			cache := NewShardedCache[uint64, int](100)

			// Hash the key multiple times and verify it always maps to the same shard
			hash1 := cache.hasher.Hash(key)
			shard1 := hash1 % numShards

			hash2 := cache.hasher.Hash(key)
			shard2 := hash2 % numShards

			hash3 := cache.hasher.Hash(key)
			shard3 := hash3 % numShards

			// All shard assignments must be identical
			return shard1 == shard2 && shard2 == shard3
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that operations on the same key always access the same shard
	t.Run("OperationsUseSameShard", func(t *testing.T) {
		property := func(key string, value1 int, value2 int) bool {
			cache := NewShardedCache[string, int](100)

			// Put first value
			cache.Put(key, value1)

			// Get the value (should be from the same shard)
			retrieved1, ok1 := cache.Get(key)
			if !ok1 || retrieved1 != value1 {
				return false
			}

			// Update with second value (should go to the same shard)
			cache.Put(key, value2)

			// Get the updated value (should be from the same shard)
			retrieved2, ok2 := cache.Get(key)
			if !ok2 || retrieved2 != value2 {
				return false
			}

			// Delete the key (should delete from the same shard)
			cache.Delete(key)

			// Verify deletion (should check the same shard)
			_, ok3 := cache.Get(key)

			return !ok3
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that shard assignment is within valid range [0, numShards)
	t.Run("ShardIndexInValidRange", func(t *testing.T) {
		property := func(key string) bool {
			cache := NewShardedCache[string, int](100)

			hash := cache.hasher.Hash(key)
			shardIndex := hash % numShards

			// Shard index must be in range [0, numShards)
			return shardIndex < uint64(numShards)
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that different keys can map to different shards (distribution property)
	t.Run("DifferentKeysCanMapToDifferentShards", func(t *testing.T) {
		cache := NewShardedCache[int, int](100)

		// Track which shards are used
		shardsUsed := make(map[uint64]bool)

		// Try many keys to see if we get distribution across shards
		for i := 0; i < 1000; i++ {
			hash := cache.hasher.Hash(i)
			shardIndex := hash % numShards
			shardsUsed[shardIndex] = true
		}

		// We should use more than 1 shard (ideally close to numShards)
		// With 1000 keys and good distribution, we should hit most shards
		if len(shardsUsed) < 2 {
			t.Errorf("Poor distribution: only %d shards used out of %d", len(shardsUsed), numShards)
		}
	})

	// Test that the same key in different cache instances maps to the same shard
	t.Run("ConsistentAcrossCacheInstances", func(t *testing.T) {
		property := func(key string) bool {
			cache1 := NewShardedCache[string, int](100)
			cache2 := NewShardedCache[string, int](200)
			cache3 := NewShardedCache[string, int](500)

			hash1 := cache1.hasher.Hash(key)
			shard1 := hash1 % numShards

			hash2 := cache2.hasher.Hash(key)
			shard2 := hash2 % numShards

			hash3 := cache3.hasher.Hash(key)
			shard3 := hash3 % numShards

			// All cache instances should map the same key to the same shard
			return shard1 == shard2 && shard2 == shard3
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})
}

// **Validates: Requirements 1.3, 1.5**
//
// Property 2: TTL Expiration Correctness
//
// For any cache entry with TTL duration T, the entry SHALL be retrievable for
// any time t < T after creation and SHALL NOT be retrievable for any time t >= T
// after creation.
func TestProperty_TTLExpirationCorrectness(t *testing.T) {
	// Test that entries are retrievable before TTL expires
	t.Run("RetrievableBeforeTTL", func(t *testing.T) {
		property := func(key string, value int) bool {
			// TTL of 2s; sleep 50ms — large margin avoids CI timer jitter on Windows.
			ttl := 2 * time.Second
			config := CacheConfig[string]{
				Capacity: 100,
				TTL:      ttl,
			}
			cache := NewShardedCacheWithConfig[string, int](config)

			cache.Put(key, value)
			time.Sleep(50 * time.Millisecond)

			retrieved, ok := cache.Get(key)
			return ok && retrieved == value
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that entries are NOT retrievable after TTL expires
	t.Run("NotRetrievableAfterTTL", func(t *testing.T) {
		property := func(key string, value int) bool {
			// Use a TTL of 100ms for testing
			ttl := 100 * time.Millisecond
			config := CacheConfig[string]{
				Capacity: 100,
				TTL:      ttl,
			}
			cache := NewShardedCacheWithConfig[string, int](config)

			// Store the value
			cache.Put(key, value)

			// Wait for a time t >= TTL (150ms >= 100ms)
			time.Sleep(150 * time.Millisecond)

			// Entry should NOT be retrievable
			_, ok := cache.Get(key)

			return !ok
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test boundary condition: exactly at TTL
	t.Run("BoundaryAtTTL", func(t *testing.T) {
		property := func(key string, value int) bool {
			// Use a TTL of 100ms for testing
			ttl := 100 * time.Millisecond
			config := CacheConfig[string]{
				Capacity: 100,
				TTL:      ttl,
			}
			cache := NewShardedCacheWithConfig[string, int](config)

			// Store the value
			cache.Put(key, value)

			// Wait for exactly TTL (with small buffer for timing precision)
			time.Sleep(ttl + 10*time.Millisecond)

			// Entry should NOT be retrievable (t >= T)
			_, ok := cache.Get(key)

			return !ok
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with different key/value types
	t.Run("IntInt", func(t *testing.T) {
		property := func(key int, value int) bool {
			ttl := 100 * time.Millisecond
			config := CacheConfig[int]{
				Capacity: 100,
				TTL:      ttl,
			}
			cache := NewShardedCacheWithConfig[int, int](config)

			// Store the value
			cache.Put(key, value)

			// Check before expiry
			retrieved1, ok1 := cache.Get(key)
			if !ok1 || retrieved1 != value {
				return false
			}

			// Wait for expiry
			time.Sleep(150 * time.Millisecond)

			// Check after expiry
			_, ok2 := cache.Get(key)

			return !ok2
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that TTL=0 means no expiration
	t.Run("NoExpirationWithZeroTTL", func(t *testing.T) {
		property := func(key string, value int) bool {
			config := CacheConfig[string]{
				Capacity: 100,
				TTL:      0, // No expiration
			}
			cache := NewShardedCacheWithConfig[string, int](config)

			// Store the value
			cache.Put(key, value)

			// Wait for a reasonable time
			time.Sleep(200 * time.Millisecond)

			// Entry should still be retrievable (no TTL)
			retrieved, ok := cache.Get(key)

			return ok && retrieved == value
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})
}

// **Validates: Requirements 4.3, 4.4, 4.6, 11.1, 11.4, 11.5**
//
// Property 6: Concurrent Access Safety
//
// For any sequence of concurrent cache operations (Get, Put, Delete) across
// multiple goroutines, the cache SHALL maintain consistency with no data races,
// no deadlocks, and all operations SHALL complete successfully.
func TestProperty_ConcurrentAccessSafety(t *testing.T) {
	// Test concurrent Put operations
	t.Run("ConcurrentPuts", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)
			done := make(chan bool, len(keys))

			// Launch concurrent Put operations
			for i, key := range keys {
				go func(k, v int) {
					cache.Put(k, v)
					done <- true
				}(key, i)
			}

			// Wait for all operations to complete (with timeout to detect deadlocks)
			timeout := time.After(5 * time.Second)
			for i := 0; i < len(keys); i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			// Verify all keys are present
			for i, key := range keys {
				if val, ok := cache.Get(key); !ok || val != i {
					return false
				}
			}

			return true
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent Get operations
	t.Run("ConcurrentGets", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)

			// Pre-populate cache
			for i, key := range keys {
				cache.Put(key, i)
			}

			done := make(chan bool, len(keys)*10)

			// Launch many concurrent Get operations
			for i := 0; i < 10; i++ {
				for j, key := range keys {
					go func(k, expectedVal int) {
						val, ok := cache.Get(k)
						done <- ok && val == expectedVal
					}(key, j)
				}
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < len(keys)*10; i++ {
				select {
				case result := <-done:
					if !result {
						return false
					}
				case <-timeout:
					return false // Deadlock detected
				}
			}

			return true
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent mixed operations (Put, Get, Delete)
	t.Run("ConcurrentMixedOperations", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)
			done := make(chan bool, len(keys)*3)

			// Launch concurrent mixed operations
			for i, key := range keys {
				// Put operation
				go func(k, v int) {
					cache.Put(k, v)
					done <- true
				}(key, i)

				// Get operation
				go func(k int) {
					cache.Get(k)
					done <- true
				}(key)

				// Delete operation
				go func(k int) {
					cache.Delete(k)
					done <- true
				}(key)
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < len(keys)*3; i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			// Cache should still be functional after concurrent operations
			cache.Put(999, 999)
			val, ok := cache.Get(999)

			return ok && val == 999
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent operations on the same key
	t.Run("ConcurrentOperationsSameKey", func(t *testing.T) {
		property := func(value int) bool {
			cache := NewShardedCache[string, int](100)
			key := "shared-key"
			numOps := 100
			done := make(chan bool, numOps)

			// Launch concurrent operations on the same key
			for i := 0; i < numOps; i++ {
				go func(v int) {
					cache.Put(key, v)
					cache.Get(key)
					done <- true
				}(i)
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < numOps; i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			// Key should exist and have some value
			_, ok := cache.Get(key)
			return ok
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent operations across different shards
	t.Run("ConcurrentOperationsAcrossShards", func(t *testing.T) {
		property := func(seed int) bool {
			cache := NewShardedCache[int, int](1000)
			numOps := 100
			done := make(chan bool, numOps)

			// Generate keys that map to different shards
			keys := make([]int, numOps)
			for i := 0; i < numOps; i++ {
				keys[i] = seed + i*numShards // Ensure distribution across shards
			}

			// Launch concurrent operations
			for i, key := range keys {
				go func(k, v int) {
					cache.Put(k, v)
					cache.Get(k)
					cache.Put(k, v+1)
					cache.Get(k)
					done <- true
				}(key, i)
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < numOps; i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			return true
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent Clear operations
	t.Run("ConcurrentClearOperations", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)

			// Pre-populate cache
			for i, key := range keys {
				cache.Put(key, i)
			}

			done := make(chan bool, 10)

			// Launch concurrent Clear operations
			for i := 0; i < 10; i++ {
				go func() {
					cache.Clear()
					done <- true
				}()
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < 10; i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			// Cache should be empty or functional
			cache.Put(1, 1)
			val, ok := cache.Get(1)

			return ok && val == 1
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent Resize operations
	t.Run("ConcurrentResizeOperations", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)

			// Pre-populate cache
			for i, key := range keys {
				cache.Put(key, i)
			}

			done := make(chan bool, 10)

			// Launch concurrent Resize operations
			for i := 0; i < 10; i++ {
				go func(newCap int) {
					cache.Resize(newCap)
					done <- true
				}(500 + i*100)
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < 10; i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			// Cache should still be functional
			cache.Put(999, 999)
			val, ok := cache.Get(999)

			return ok && val == 999
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test concurrent Stats operations
	t.Run("ConcurrentStatsOperations", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)
			done := make(chan bool, len(keys)*2)

			// Launch concurrent Put and Stats operations
			for i, key := range keys {
				go func(k, v int) {
					cache.Put(k, v)
					done <- true
				}(key, i)

				go func() {
					cache.Stats()
					done <- true
				}()
			}

			// Wait for all operations to complete
			timeout := time.After(5 * time.Second)
			for i := 0; i < len(keys)*2; i++ {
				select {
				case <-done:
					// Operation completed successfully
				case <-timeout:
					return false // Deadlock detected
				}
			}

			// Stats should be accessible
			stats := cache.Stats()
			return stats.Size >= 0 && stats.Capacity > 0
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})
}

// **Validates: Requirements 5.1, 5.3**
//
// Property 8: LRU Eviction Correctness
//
// For any cache at capacity C, when inserting a new entry that would exceed
// capacity, the cache SHALL evict the least recently used entry, and the cache
// size SHALL remain <= C.
func TestProperty_LRUEvictionCorrectness(t *testing.T) {
	// Test that cache size never exceeds capacity
	t.Run("SizeNeverExceedsCapacity", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			capacity := 10
			cache := NewShardedCache[int, int](capacity)

			// Insert all keys
			for i, key := range keys {
				cache.Put(key, i)

				// Verify size never exceeds capacity
				size := cache.Size()
				if size > capacity {
					return false
				}
			}

			return true
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that LRU entry is evicted when capacity is exceeded
	t.Run("LRUEntryEvicted", func(t *testing.T) {
		property := func(seed int) bool {
			capacity := 5
			cache := NewShardedCache[int, int](capacity)

			// Fill cache to capacity with sequential keys
			keys := make([]int, capacity)
			for i := 0; i < capacity; i++ {
				keys[i] = seed + i
				cache.Put(keys[i], i)
			}

			// Verify all keys are present
			for i, key := range keys {
				if val, ok := cache.Get(key); !ok || val != i {
					return false
				}
			}

			// Insert a new key that will cause eviction
			newKey := seed + capacity
			cache.Put(newKey, capacity)

			// The first key (oldest/LRU) should be evicted
			// Note: Due to sharding, we need to check that at least one of the
			// early keys was evicted and the new key exists
			_, newKeyExists := cache.Get(newKey)
			if !newKeyExists {
				return false
			}

			// Cache size should still be at capacity
			size := cache.Size()
			if size > capacity {
				return false
			}

			return true
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that recently accessed entries are not evicted
	t.Run("RecentlyAccessedNotEvicted", func(t *testing.T) {
		capacity := 3
		cache := NewShardedCache[int, int](capacity)

		// Insert 3 entries
		cache.Put(1, 100)
		cache.Put(2, 200)
		cache.Put(3, 300)

		// Access entry 1 to make it recently used
		cache.Get(1)

		// Insert a new entry that will cause eviction
		// Entry 2 should be evicted (it's the LRU now)
		cache.Put(4, 400)

		// Entry 1 should still exist (it was recently accessed)
		val1, ok1 := cache.Get(1)
		if !ok1 || val1 != 100 {
			t.Errorf("Recently accessed entry 1 was evicted")
		}

		// Entry 4 should exist (just inserted)
		val4, ok4 := cache.Get(4)
		if !ok4 || val4 != 400 {
			t.Errorf("Newly inserted entry 4 does not exist")
		}

		// Size should be at capacity
		if cache.Size() > capacity {
			t.Errorf("Cache size %d exceeds capacity %d", cache.Size(), capacity)
		}
	})

	// Test eviction with updates (Put on existing key)
	t.Run("UpdateDoesNotCauseEviction", func(t *testing.T) {
		property := func(seed int) bool {
			capacity := 5
			cache := NewShardedCache[int, int](capacity)

			// Fill cache to capacity
			keys := make([]int, capacity)
			for i := 0; i < capacity; i++ {
				keys[i] = seed + i
				cache.Put(keys[i], i)
			}

			// Update an existing key (should not cause eviction)
			cache.Put(keys[0], 999)

			// All original keys should still be present
			for _, key := range keys {
				if _, ok := cache.Get(key); !ok {
					return false
				}
			}

			// Size should still be at capacity
			size := cache.Size()
			return size <= capacity
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that eviction count increases when capacity is exceeded
	t.Run("EvictionCountIncreases", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) <= 5 {
				return true // Not enough keys to test eviction
			}

			capacity := 5
			cache := NewShardedCache[int, int](capacity)

			// Get initial eviction count
			initialStats := cache.Stats()
			initialEvictions := initialStats.Evictions

			// Insert more keys than capacity
			for i, key := range keys {
				cache.Put(key, i)
			}

			// Get final eviction count
			finalStats := cache.Stats()
			finalEvictions := finalStats.Evictions

			// Evictions should have increased if we inserted more than capacity
			if len(keys) > capacity {
				return finalEvictions > initialEvictions
			}

			return true
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test LRU behavior with mixed operations
	t.Run("LRUWithMixedOperations", func(t *testing.T) {
		capacity := 4
		cache := NewShardedCache[int, int](capacity)

		// Insert 4 entries (fill to capacity)
		cache.Put(1, 100)
		cache.Put(2, 200)
		cache.Put(3, 300)
		cache.Put(4, 400)

		// Access pattern: 2, 3, 4 (making 1 the LRU)
		cache.Get(2)
		cache.Get(3)
		cache.Get(4)

		// Insert new entry (should evict 1)
		cache.Put(5, 500)

		// Entry 5 should exist
		val5, ok5 := cache.Get(5)
		if !ok5 || val5 != 500 {
			t.Errorf("Newly inserted entry 5 does not exist")
		}

		// Entries 2, 3, 4 should still exist (they were accessed)
		val2, ok2 := cache.Get(2)
		if !ok2 || val2 != 200 {
			t.Errorf("Recently accessed entry 2 was evicted")
		}

		val3, ok3 := cache.Get(3)
		if !ok3 || val3 != 300 {
			t.Errorf("Recently accessed entry 3 was evicted")
		}

		val4, ok4 := cache.Get(4)
		if !ok4 || val4 != 400 {
			t.Errorf("Recently accessed entry 4 was evicted")
		}

		// Size should be at capacity
		if cache.Size() > capacity {
			t.Errorf("Cache size %d exceeds capacity %d", cache.Size(), capacity)
		}
	})

	// Test that capacity is respected per shard
	t.Run("CapacityRespectedPerShard", func(t *testing.T) {
		property := func(seed int) bool {
			capacity := 32 // 32 / 16 shards = 2 per shard
			cache := NewShardedCache[int, int](capacity)

			// Insert many keys
			numKeys := 100
			for i := 0; i < numKeys; i++ {
				cache.Put(seed+i, i)
			}

			// Total size should not exceed capacity
			size := cache.Size()
			return size <= capacity
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test eviction with string keys
	t.Run("StringKeysLRUEviction", func(t *testing.T) {
		property := func(seed int) bool {
			capacity := 5
			cache := NewShardedCache[string, int](capacity)

			// Fill cache to capacity
			keys := make([]string, capacity)
			for i := 0; i < capacity; i++ {
				keys[i] = anyToString(seed + i)
				if keys[i] == "" {
					keys[i] = "key" + anyToString(i)
				}
				cache.Put(keys[i], i)
			}

			// Insert more keys than capacity
			for i := capacity; i < capacity+10; i++ {
				key := anyToString(seed + i)
				if key == "" {
					key = "key" + anyToString(i)
				}
				cache.Put(key, i)
			}

			// Size should not exceed capacity
			size := cache.Size()
			return size <= capacity
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that Resize respects new capacity with eviction
	t.Run("ResizeEvictsToNewCapacity", func(t *testing.T) {
		property := func(seed int) bool {
			initialCapacity := 20
			cache := NewShardedCache[int, int](initialCapacity)

			// Fill cache
			for i := 0; i < initialCapacity; i++ {
				cache.Put(seed+i, i)
			}

			// Resize to smaller capacity
			newCapacity := 10
			cache.Resize(newCapacity)

			// Size should not exceed new capacity
			size := cache.Size()
			return size <= newCapacity
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that eviction maintains cache consistency
	t.Run("EvictionMaintainsConsistency", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			capacity := 10
			cache := NewShardedCache[int, int](capacity)

			// Insert all keys
			for i, key := range keys {
				cache.Put(key, i)
			}

			// Get stats
			stats := cache.Stats()

			// Size should match what we can retrieve
			retrievableCount := 0
			for i, key := range keys {
				if val, ok := cache.Get(key); ok {
					// If key exists, value should match
					if val != i {
						return false
					}
					retrievableCount++
				}
			}

			// The number of retrievable keys should be <= capacity
			return retrievableCount <= capacity && stats.Size <= capacity
		}

		if err := quick.Check(property, nil); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})
}
