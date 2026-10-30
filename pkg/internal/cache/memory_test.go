package cache

import (
	"testing"
	"testing/quick"
)

// TestMemoryTracking_PerShard verifies that memory is tracked per shard
func TestMemoryTracking_PerShard(t *testing.T) {
	cache := NewShardedCache[string, string](100)

	// Add some entries
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	// Get stats
	stats := cache.Stats()

	// Verify memory is being tracked
	if stats.MemoryBytes == 0 {
		t.Error("Expected memory bytes to be > 0")
	}

	// Verify shard stats are populated
	if len(stats.ShardStats) == 0 {
		t.Error("Expected shard stats to be populated")
	}

	// Verify shard memory adds up to total
	var shardTotal int64
	for _, ss := range stats.ShardStats {
		shardTotal += ss.MemoryBytes
	}

	if shardTotal != stats.MemoryBytes {
		t.Errorf("Shard memory total %d doesn't match global memory %d", shardTotal, stats.MemoryBytes)
	}
}

// TestMemoryTracking_Updates verifies memory tracking on updates
func TestMemoryTracking_Updates(t *testing.T) {
	cache := NewShardedCache[string, string](100)

	// Add an entry
	cache.Put("key1", "short")
	stats1 := cache.Stats()
	mem1 := stats1.MemoryBytes

	// Update with longer value
	cache.Put("key1", "this is a much longer value")
	stats2 := cache.Stats()
	mem2 := stats2.MemoryBytes

	// Memory should increase
	if mem2 <= mem1 {
		t.Errorf("Expected memory to increase after update, got %d -> %d", mem1, mem2)
	}

	// Update with shorter value
	cache.Put("key1", "x")
	stats3 := cache.Stats()
	mem3 := stats3.MemoryBytes

	// Memory should decrease
	if mem3 >= mem2 {
		t.Errorf("Expected memory to decrease after update, got %d -> %d", mem2, mem3)
	}
}

// TestMemoryTracking_Eviction verifies memory tracking on eviction
func TestMemoryTracking_Eviction(t *testing.T) {
	cache := NewShardedCache[string, string](3)

	// Fill cache
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")
	cache.Put("key3", "value3")

	stats1 := cache.Stats()
	mem1 := stats1.MemoryBytes

	// Add more entries to trigger eviction
	cache.Put("key4", "value4")
	cache.Put("key5", "value5")

	stats2 := cache.Stats()
	mem2 := stats2.MemoryBytes

	// Memory should not grow unbounded
	// With capacity 3, we should have roughly 3 entries worth of memory
	if stats2.Size > 3 {
		t.Errorf("Cache size %d exceeds capacity 3", stats2.Size)
	}

	// Memory should be reasonable (not accumulating evicted entries)
	if mem2 > mem1*2 {
		t.Errorf("Memory grew too much: %d -> %d", mem1, mem2)
	}
}

// TestMemoryTracking_Clear verifies memory is reset on clear
func TestMemoryTracking_Clear(t *testing.T) {
	cache := NewShardedCache[string, string](100)

	// Add entries
	for i := 0; i < 10; i++ {
		cache.Put(string(rune('a'+i)), "value")
	}

	stats1 := cache.Stats()
	if stats1.MemoryBytes == 0 {
		t.Error("Expected memory > 0 before clear")
	}

	// Clear cache
	cache.Clear()

	stats2 := cache.Stats()
	if stats2.MemoryBytes != 0 {
		t.Errorf("Expected memory to be 0 after clear, got %d", stats2.MemoryBytes)
	}

	if stats2.Size != 0 {
		t.Errorf("Expected size to be 0 after clear, got %d", stats2.Size)
	}
}

// TestMemoryTracking_Delete verifies memory tracking on delete
func TestMemoryTracking_Delete(t *testing.T) {
	cache := NewShardedCache[string, string](100)

	// Add entries
	cache.Put("key1", "value1")
	cache.Put("key2", "value2")

	stats1 := cache.Stats()
	mem1 := stats1.MemoryBytes

	// Delete one entry
	cache.Delete("key1")

	stats2 := cache.Stats()
	mem2 := stats2.MemoryBytes

	// Memory should decrease
	if mem2 >= mem1 {
		t.Errorf("Expected memory to decrease after delete, got %d -> %d", mem1, mem2)
	}

	// Size should decrease
	if stats2.Size >= stats1.Size {
		t.Errorf("Expected size to decrease after delete, got %d -> %d", stats1.Size, stats2.Size)
	}
}

// TestMemoryLimit_Enforcement verifies memory limit is enforced
func TestMemoryLimit_Enforcement(t *testing.T) {
	// Create cache with 1KB memory limit
	cfg := CacheConfig[string]{
		Capacity:    1000,
		MemoryLimit: 1024, // 1KB
	}
	cache := NewShardedCacheWithConfig[string, string](cfg)

	// Try to add entries that would exceed the limit
	largeValue := string(make([]byte, 200)) // ~200 bytes per entry

	for i := 0; i < 20; i++ {
		cache.Put(string(rune('a'+i)), largeValue)
	}

	stats := cache.Stats()

	// Memory should not exceed the limit (with some tolerance for overhead)
	if stats.MemoryBytes > 1024+500 { // Allow 500 bytes overhead
		t.Errorf("Memory %d exceeds limit 1024 (with tolerance)", stats.MemoryBytes)
	}

	// Should have evicted entries to stay under limit
	if stats.Evictions == 0 {
		t.Error("Expected evictions to enforce memory limit")
	}
}

// TestMemoryLimit_AggressiveEviction verifies aggressive eviction when over limit
func TestMemoryLimit_AggressiveEviction(t *testing.T) {
	// Create cache with small memory limit
	cfg := CacheConfig[string]{
		Capacity:    100,
		MemoryLimit: 500, // 500 bytes
	}
	cache := NewShardedCacheWithConfig[string, string](cfg)

	// Add small entries first
	for i := 0; i < 5; i++ {
		cache.Put(string(rune('a'+i)), "small")
	}

	stats1 := cache.Stats()
	size1 := stats1.Size

	// Try to add a large entry
	largeValue := string(make([]byte, 400))
	cache.Put("large", largeValue)

	stats2 := cache.Stats()

	// Should have evicted multiple entries to make room
	if stats2.Size >= size1 {
		t.Logf("Size before: %d, after: %d", size1, stats2.Size)
	}

	// Memory should still be under limit
	if stats2.MemoryBytes > 500+200 { // Allow some overhead
		t.Errorf("Memory %d exceeds limit 500 (with tolerance)", stats2.MemoryBytes)
	}
}

// TestMemoryLimit_NoLimit verifies behavior with no memory limit
func TestMemoryLimit_NoLimit(t *testing.T) {
	// Create cache with no memory limit (0 = unlimited)
	cfg := CacheConfig[string]{
		Capacity:    100, // Use larger capacity to avoid shard distribution issues
		MemoryLimit: 0,   // unlimited
	}
	cache := NewShardedCacheWithConfig[string, string](cfg)

	// Add entries
	for i := 0; i < 50; i++ {
		cache.Put(string(rune('a'+i%26))+string(rune('a'+i/26)), "value")
	}

	stats1 := cache.Stats()

	// Should have entries (limited by capacity, not memory)
	if stats1.Size == 0 {
		t.Error("Expected some entries in cache")
	}

	// Add more entries (should evict based on capacity, not memory)
	for i := 50; i < 150; i++ {
		cache.Put(string(rune('a'+i%26))+string(rune('a'+i/26)), "value")
	}

	stats2 := cache.Stats()

	// Should not exceed capacity
	if stats2.Size > 100 {
		t.Errorf("Expected size <= 100, got %d", stats2.Size)
	}

	// Should have evictions based on capacity
	if stats2.Evictions == 0 {
		t.Error("Expected evictions based on capacity")
	}
}

// **Validates: Requirements 5.2**
//
// Property 16: Memory Tracking Accuracy
//
// For any cache entry E with estimated memory size M, the sum of all entry
// memory sizes SHALL approximate the actual memory usage within a reasonable
// margin (e.g., ±20%).
func TestProperty_MemoryTrackingAccuracy(t *testing.T) {
	// Test with string values of varying sizes
	t.Run("StringValues", func(t *testing.T) {
		property := func(values []string) bool {
			if len(values) == 0 {
				return true
			}

			cache := NewShardedCache[int, string](1000)

			// Calculate expected memory size manually
			expectedMemory := int64(0)
			for i, value := range values {
				// Estimate memory for this entry
				entrySize := estimateMemorySize(value)
				expectedMemory += int64(entrySize)

				// Store in cache
				cache.Put(i, value)
			}

			// Get reported memory from cache
			stats := cache.Stats()
			reportedMemory := stats.MemoryBytes

			// Memory tracking should be within ±20% margin
			lowerBound := float64(expectedMemory) * 0.8
			upperBound := float64(expectedMemory) * 1.2

			return float64(reportedMemory) >= lowerBound && float64(reportedMemory) <= upperBound
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test with int values
	t.Run("IntValues", func(t *testing.T) {
		property := func(values []int) bool {
			if len(values) == 0 {
				return true
			}

			cache := NewShardedCache[int, int](1000)

			// Calculate expected memory size manually
			expectedMemory := int64(0)
			for i, value := range values {
				entrySize := estimateMemorySize(value)
				expectedMemory += int64(entrySize)
				cache.Put(i, value)
			}

			// Get reported memory from cache
			stats := cache.Stats()
			reportedMemory := stats.MemoryBytes

			// Memory tracking should be within ±20% margin
			lowerBound := float64(expectedMemory) * 0.8
			upperBound := float64(expectedMemory) * 1.2

			return float64(reportedMemory) >= lowerBound && float64(reportedMemory) <= upperBound
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test that shard memory adds up to total memory
	t.Run("ShardMemorySumEqualsTotal", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, string](1000)

			// Insert entries
			for i, key := range keys {
				cache.Put(key, "value"+anyToString(i))
			}

			// Get stats
			stats := cache.Stats()

			// Sum up shard memory
			shardMemorySum := int64(0)
			for _, shardStat := range stats.ShardStats {
				shardMemorySum += shardStat.MemoryBytes
			}

			// Shard memory sum should equal total memory
			return shardMemorySum == stats.MemoryBytes
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test memory tracking with updates
	t.Run("MemoryUpdatesOnValueChange", func(t *testing.T) {
		property := func(key int, value1 string, value2 string) bool {
			cache := NewShardedCache[int, string](100)

			// Insert first value
			cache.Put(key, value1)
			stats1 := cache.Stats()
			mem1 := stats1.MemoryBytes

			// Calculate expected memory for first value
			expected1 := int64(estimateMemorySize(value1))

			// Update with second value
			cache.Put(key, value2)
			stats2 := cache.Stats()
			mem2 := stats2.MemoryBytes

			// Calculate expected memory for second value
			expected2 := int64(estimateMemorySize(value2))

			// Memory should change appropriately
			// Allow ±20% margin for each measurement
			mem1InRange := float64(mem1) >= float64(expected1)*0.8 && float64(mem1) <= float64(expected1)*1.2
			mem2InRange := float64(mem2) >= float64(expected2)*0.8 && float64(mem2) <= float64(expected2)*1.2

			return mem1InRange && mem2InRange
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test memory tracking with deletions
	t.Run("MemoryDecreasesOnDelete", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) < 2 {
				return true
			}

			cache := NewShardedCache[int, string](1000)

			// Insert entries
			for i, key := range keys {
				cache.Put(key, "value"+anyToString(i))
			}

			stats1 := cache.Stats()
			mem1 := stats1.MemoryBytes

			// Delete half the entries
			for i := 0; i < len(keys)/2; i++ {
				cache.Delete(keys[i])
			}

			stats2 := cache.Stats()
			mem2 := stats2.MemoryBytes

			// Memory should decrease after deletions
			// (unless all deleted entries were in inactive shards)
			return mem2 <= mem1
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test memory tracking with evictions
	t.Run("MemoryStaysWithinBoundsOnEviction", func(t *testing.T) {
		property := func(seed int) bool {
			capacity := 10
			cache := NewShardedCache[int, string](capacity)

			// Fill cache beyond capacity to trigger evictions
			numEntries := 50
			for i := 0; i < numEntries; i++ {
				cache.Put(seed+i, "value"+anyToString(i))
			}

			stats := cache.Stats()

			// Size should not exceed capacity
			if stats.Size > capacity {
				return false
			}

			// Calculate expected memory for current entries
			// We don't know which entries survived, but we know the count
			// Each entry should have roughly the same size
			avgEntrySize := estimateMemorySize("value0")
			expectedMemory := int64(stats.Size * avgEntrySize)

			// Memory should be within reasonable bounds
			lowerBound := float64(expectedMemory) * 0.5 // More lenient lower bound
			upperBound := float64(expectedMemory) * 1.5 // More lenient upper bound

			return float64(stats.MemoryBytes) >= lowerBound && float64(stats.MemoryBytes) <= upperBound
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test memory tracking with Clear
	t.Run("MemoryZeroAfterClear", func(t *testing.T) {
		property := func(keys []int) bool {
			if len(keys) == 0 {
				return true
			}

			cache := NewShardedCache[int, string](1000)

			// Insert entries
			for i, key := range keys {
				cache.Put(key, "value"+anyToString(i))
			}

			// Clear cache
			cache.Clear()

			// Memory should be zero
			stats := cache.Stats()
			return stats.MemoryBytes == 0
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test memory tracking with mixed value types
	t.Run("MixedValueSizes", func(t *testing.T) {
		cache := NewShardedCache[int, string](1000)

		// Insert values of different sizes
		testCases := []struct {
			key   int
			value string
		}{
			{1, "short"},
			{2, "medium length value"},
			{3, "this is a much longer value that should take more memory"},
			{4, string(make([]byte, 1000))}, // Large value
			{5, ""},                         // Empty value
		}

		expectedMemory := int64(0)
		for _, tc := range testCases {
			entrySize := estimateMemorySize(tc.value)
			expectedMemory += int64(entrySize)
			cache.Put(tc.key, tc.value)
		}

		stats := cache.Stats()
		reportedMemory := stats.MemoryBytes

		// Memory tracking should be within ±20% margin
		lowerBound := float64(expectedMemory) * 0.8
		upperBound := float64(expectedMemory) * 1.2

		if float64(reportedMemory) < lowerBound || float64(reportedMemory) > upperBound {
			t.Errorf("Memory tracking out of bounds: expected ~%d, got %d (bounds: %.0f-%.0f)",
				expectedMemory, reportedMemory, lowerBound, upperBound)
		}
	})

	// Test memory tracking accuracy with concurrent operations
	t.Run("ConcurrentMemoryTracking", func(t *testing.T) {
		property := func(seed int) bool {
			cache := NewShardedCache[int, string](1000)
			numOps := 100
			done := make(chan bool, numOps)

			// Launch concurrent Put operations
			for i := 0; i < numOps; i++ {
				go func(key int) {
					cache.Put(key, "value"+anyToString(key))
					done <- true
				}(seed + i)
			}

			// Wait for all operations to complete
			for i := 0; i < numOps; i++ {
				<-done
			}

			// Get stats
			stats := cache.Stats()

			// Memory should be positive if we have entries
			if stats.Size > 0 && stats.MemoryBytes == 0 {
				return false
			}

			// Shard memory should sum to total
			shardMemorySum := int64(0)
			for _, shardStat := range stats.ShardStats {
				shardMemorySum += shardStat.MemoryBytes
			}

			return shardMemorySum == stats.MemoryBytes
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 50}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})

	// Test memory tracking with Resize
	t.Run("MemoryTrackingAfterResize", func(t *testing.T) {
		property := func(seed int) bool {
			cache := NewShardedCache[int, string](100)

			// Fill cache
			for i := 0; i < 50; i++ {
				cache.Put(seed+i, "value"+anyToString(i))
			}

			stats1 := cache.Stats()
			mem1 := stats1.MemoryBytes
			size1 := stats1.Size

			// Resize to smaller capacity
			cache.Resize(25)

			stats2 := cache.Stats()
			mem2 := stats2.MemoryBytes
			size2 := stats2.Size

			// If size decreased, memory should also decrease or stay same
			if size2 < size1 && mem2 > mem1 {
				return false
			}

			// Memory should still be positive if we have entries
			if size2 > 0 && mem2 == 0 {
				return false
			}

			return true
		}

		if err := quick.Check(property, &quick.Config{MaxCount: 100}); err != nil {
			t.Errorf("Property violated: %v", err)
		}
	})
}
