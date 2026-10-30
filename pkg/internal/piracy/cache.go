// Package piracy — cache_fixed.go
// LRU cache with size eviction — 16-way sharded (P20)
package piracy

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

const cacheShardCount = 16
const cacheShardMinSize = 64

// ═══════════════════════════════════════════════════════════════════════════════
// LRU CACHE — sharded
// ═══════════════════════════════════════════════════════════════════════════════

type CacheEntry struct {
	Hash          string
	Result        *Result
	Timestamp     time.Time
	ConfigVersion int
}

type cacheShard struct {
	mu      sync.RWMutex
	entries map[string]*list.Element
	lru     *list.List
}

type ResultCache struct {
	shards   [cacheShardCount]cacheShard
	hits     int64
	misses   int64
	maxSize  int
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

func (c *ResultCache) shardFor(hash string) int {
	if c != nil && c.maxSize < cacheShardCount {
		return 0
	}
	if len(hash) == 0 {
		return 0
	}
	var h uint32
	for i := 0; i < 4 && i < len(hash); i++ {
		h = h*31 + uint32(hash[i])
	}
	return int(h % cacheShardCount)
}

func NewResultCache(maxSize int, ttl time.Duration) *ResultCache {
	if maxSize < 1 {
		maxSize = 1
	}
	cache := &ResultCache{
		maxSize: maxSize,
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	for i := range cache.shards {
		cache.shards[i].entries = make(map[string]*list.Element)
		cache.shards[i].lru = list.New()
	}
	if ttl > 0 {
		go cache.cleanup()
	}
	return cache
}

// Get возвращает результат из кэша
func (c *ResultCache) Get(content []byte, configVersion int) (*Result, bool) {
	hash := hashContent(content)
	shardIdx := c.shardFor(hash)
	sh := &c.shards[shardIdx]
	sh.mu.Lock()
	elem, ok := sh.entries[hash]
	if !ok {
		sh.mu.Unlock()
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}
	cached := elem.Value.(CacheEntry)
	if cached.ConfigVersion != configVersion {
		sh.lru.Remove(elem)
		delete(sh.entries, hash)
		sh.mu.Unlock()
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}
	if c.ttl > 0 && time.Since(cached.Timestamp) > c.ttl {
		sh.lru.Remove(elem)
		delete(sh.entries, hash)
		sh.mu.Unlock()
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}
	sh.lru.MoveToFront(elem)
	sh.mu.Unlock()
	atomic.AddInt64(&c.hits, 1)
	return cloneResult(cached.Result), true
}

// Set сохраняет результат в кэш
func (c *ResultCache) Set(content []byte, result *Result, configVersion int) {
	hash := hashContent(content)
	shardIdx := c.shardFor(hash)
	sh := &c.shards[shardIdx]
	entry := CacheEntry{
		Hash:          hash,
		Result:        cloneResult(result),
		Timestamp:     time.Now(),
		ConfigVersion: configVersion,
	}
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if elem, ok := sh.entries[hash]; ok {
		sh.lru.MoveToFront(elem)
		elem.Value = entry
		return
	}
	perShard := c.maxSize / cacheShardCount
	if c.maxSize < cacheShardCount {
		perShard = c.maxSize
	} else if perShard < cacheShardMinSize {
		perShard = cacheShardMinSize
	}
	if perShard < 1 {
		perShard = 1
	}
	if sh.lru.Len() >= perShard {
		oldest := sh.lru.Back()
		if oldest != nil {
			sh.lru.Remove(oldest)
			oldEntry := oldest.Value.(CacheEntry)
			delete(sh.entries, oldEntry.Hash)
		}
	}
	elem := sh.lru.PushFront(entry)
	sh.entries[hash] = elem
}

// Stats возвращает статистику кэша
func (c *ResultCache) Stats() (hits, misses int64, hitRate float64) {
	h := atomic.LoadInt64(&c.hits)
	m := atomic.LoadInt64(&c.misses)
	total := h + m
	if total == 0 {
		return h, m, 0
	}
	return h, m, float64(h) / float64(total)
}

// Clear очищает кэш
func (c *ResultCache) Clear() {
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		sh.entries = make(map[string]*list.Element)
		sh.lru = list.New()
		sh.mu.Unlock()
	}
	atomic.StoreInt64(&c.hits, 0)
	atomic.StoreInt64(&c.misses, 0)
}

// Close stops the maintenance goroutine. Call it for short-lived caches (for
// example tests or one-shot CLI scans) to avoid retaining the cache forever.
func (c *ResultCache) Close() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// cleanup периодически удаляет устаревшие записи
func (c *ResultCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
		}
		if c.ttl == 0 {
			continue
		}
		now := time.Now()
		for i := range c.shards {
			sh := &c.shards[i]
			sh.mu.Lock()
			var toRemove []*list.Element
			for elem := sh.lru.Front(); elem != nil; elem = elem.Next() {
				entry := elem.Value.(CacheEntry)
				if now.Sub(entry.Timestamp) > c.ttl {
					toRemove = append(toRemove, elem)
				}
			}
			for _, elem := range toRemove {
				entry := elem.Value.(CacheEntry)
				sh.lru.Remove(elem)
				delete(sh.entries, entry.Hash)
			}
			sh.mu.Unlock()
		}
	}
}

// cloneResult prevents callers from mutating cached findings through shared
// slice backing arrays. Cache results are treated as immutable snapshots.
func cloneResult(result *Result) *Result {
	if result == nil {
		return nil
	}
	copyResult := *result
	copyResult.Findings = make([]Finding, len(result.Findings))
	for i, finding := range result.Findings {
		copyResult.Findings[i] = finding
		copyResult.Findings[i].RiskTags = append([]string(nil), finding.RiskTags...)
	}
	copyResult.SitesFound = append([]string(nil), result.SitesFound...)
	copyResult.ModIndicators = append([]string(nil), result.ModIndicators...)
	copyResult.RiskTags = append([]string(nil), result.RiskTags...)
	return &copyResult
}

// hashContent вычисляет SHA256 хэш контента. Callers already cap input size
// (MaxAnalysisSize, 10MB) well before SHA256 throughput would matter, so this
// always hashes the full content — a partial hash risks caching the wrong
// result for a file whose sampled bytes happen to collide.
func hashContent(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
