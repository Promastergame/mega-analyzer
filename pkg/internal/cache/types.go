package cache

import "time"

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

// CacheInterface defines the common interface for all caches
type CacheInterface[K comparable, V any] interface {
	// Get retrieves a value from the cache
	Get(key K) (V, bool)

	// Put stores a value in the cache
	Put(key K, value V)

	// Delete removes a value from the cache
	Delete(key K)

	// Clear empties the entire cache
	Clear()

	// Size returns the current number of entries
	Size() int

	// Capacity returns the maximum number of entries
	Capacity() int

	// Stats returns comprehensive cache statistics
	Stats() CacheStats

	// Resize changes the cache capacity
	Resize(newCapacity int)
}

// CacheConfig controls cache behavior
type CacheConfig[K comparable] struct {
	Capacity    int           // total capacity across all shards
	TTL         time.Duration // 0 = no expiry
	Hasher      Hasher[K]     // optional custom hasher
	MemoryLimit int64         // bytes, 0 = unlimited
	ShardCount  int           // number of shards (default: 16)
}

// CacheStats contains comprehensive cache metrics
type CacheStats struct {
	Hits        int64        // number of cache hits
	Misses      int64        // number of cache misses
	Evictions   int64        // number of evictions
	Size        int          // current number of entries
	Capacity    int          // maximum number of entries
	HitRate     float64      // hit rate (hits / (hits + misses))
	MemoryBytes int64        // approximate memory usage in bytes
	MemoryMB    float64      // approximate memory usage in MB
	ShardStats  []ShardStats // per-shard breakdown
}

// ShardStats contains statistics for a single shard
type ShardStats struct {
	ShardID     int   // shard identifier (0-15)
	Size        int   // number of entries in this shard
	Hits        int64 // number of hits in this shard
	Evictions   int64 // number of evictions in this shard
	MemoryBytes int64 // approximate memory usage in bytes
}

// EntryMetadata tracks metadata for cache entries
type EntryMetadata struct {
	CreatedAt   time.Time // when the entry was created
	LastAccess  time.Time // when the entry was last accessed
	AccessCount int64     // number of times the entry was accessed
	MemorySize  int       // estimated memory size in bytes
	Version     uint64    // version number for invalidation
}
