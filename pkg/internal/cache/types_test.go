package cache

import "testing"

// TestShardedCacheImplementsCacheInterface verifies that ShardedCache implements CacheInterface
func TestShardedCacheImplementsCacheInterface(t *testing.T) {
	// This is a compile-time check
	var _ CacheInterface[string, int] = &ShardedCache[string, int]{}
	var _ CacheInterface[int, string] = &ShardedCache[int, string]{}
	var _ CacheInterface[uint64, []byte] = &ShardedCache[uint64, []byte]{}
}

// TestCacheConfigFields verifies CacheConfig has all required fields
func TestCacheConfigFields(t *testing.T) {
	cfg := CacheConfig[string]{
		Capacity:    1000,
		TTL:         0,
		Hasher:      nil,
		MemoryLimit: 1024 * 1024,
		ShardCount:  16,
	}

	if cfg.Capacity != 1000 {
		t.Errorf("Expected Capacity 1000, got %d", cfg.Capacity)
	}
	if cfg.MemoryLimit != 1024*1024 {
		t.Errorf("Expected MemoryLimit 1048576, got %d", cfg.MemoryLimit)
	}
	if cfg.ShardCount != 16 {
		t.Errorf("Expected ShardCount 16, got %d", cfg.ShardCount)
	}
}

// TestCacheStatsFields verifies CacheStats has all required fields
func TestCacheStatsFields(t *testing.T) {
	stats := CacheStats{
		Hits:        100,
		Misses:      50,
		Evictions:   10,
		Size:        90,
		Capacity:    100,
		HitRate:     0.67,
		MemoryBytes: 1024,
		MemoryMB:    0.001,
		ShardStats:  []ShardStats{},
	}

	if stats.Hits != 100 {
		t.Errorf("Expected Hits 100, got %d", stats.Hits)
	}
	if stats.ShardStats == nil {
		t.Error("ShardStats should not be nil")
	}
}

// TestShardStatsFields verifies ShardStats has all required fields
func TestShardStatsFields(t *testing.T) {
	shard := ShardStats{
		ShardID:     5,
		Size:        10,
		Hits:        50,
		Evictions:   2,
		MemoryBytes: 512,
	}

	if shard.ShardID != 5 {
		t.Errorf("Expected ShardID 5, got %d", shard.ShardID)
	}
	if shard.MemoryBytes != 512 {
		t.Errorf("Expected MemoryBytes 512, got %d", shard.MemoryBytes)
	}
}

// TestEntryMetadataFields verifies EntryMetadata has all required fields
func TestEntryMetadataFields(t *testing.T) {
	meta := EntryMetadata{
		AccessCount: 10,
		MemorySize:  256,
		Version:     1,
	}

	if meta.AccessCount != 10 {
		t.Errorf("Expected AccessCount 10, got %d", meta.AccessCount)
	}
	if meta.MemorySize != 256 {
		t.Errorf("Expected MemorySize 256, got %d", meta.MemorySize)
	}
	if meta.Version != 1 {
		t.Errorf("Expected Version 1, got %d", meta.Version)
	}
}
