package cfg

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CFG CACHE — Sharded LRU · TTL · Memory Budget · Singleflight
// ═══════════════════════════════════════════════════════════════════════════════
//
// Design notes:
//
//   • 128-bit keys (maphash ⊕ FNV-1a). A 64-bit key alone makes silent
//     collisions — and therefore *wrong CFGs* — a real possibility at scale.
//     Hashing is zero-alloc: strings are fed straight into the hashers,
//     every field is length-prefixed so ("ab","c") ≠ ("a","bc").
//
//   • 16 shards, selected by the *high* bits of the key (the map already
//     consumes the low bits). Shards are value-embedded and padded so hot
//     mutexes never share a cache line.
//
//   • Singleflight per key: N concurrent misses on the same method produce
//     exactly one build. Waiters block on the leader instead of duplicating
//     the most expensive operation in the system.
//
//   • Two eviction axes: entry count and (optional) byte budget. Memory is
//     tracked incrementally per shard — Stats() is O(shards), not O(entries).
//
//   • Builders live in a sync.Pool: the cache never assumes a Builder is
//     safe for concurrent use, and never allocates one per call either.
//
//   • Every counter is atomic; Capacity is atomic too, so Resize() races
//     with nobody.
// ═══════════════════════════════════════════════════════════════════════════════

const (
	shardBits = 4
	numShards = 1 << shardBits
	shardMask = numShards - 1

	cacheLine = 64
)

// Builder produces a CFG from a BuildInput. Implementations need NOT be
// goroutine-safe: the cache pools them and never shares one across goroutines.
type Builder interface {
	Build(BuildInput) *ControlFlowGraph
}

// Compile-time guarantee that the default builder satisfies the interface.
var _ Builder = (*CFGBuilder)(nil)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

// CacheConfig controls cache behaviour. Zero values mean "use the default".
type CacheConfig struct {
	// Capacity is the maximum number of entries across all shards.
	Capacity int
	// MaxMemory is an approximate byte budget across all shards (0 = unlimited).
	// Entries are evicted LRU-first until the budget is satisfied.
	MaxMemory int64
	// TTL bounds entry lifetime (0 = entries never expire).
	TTL time.Duration
	// NewBuilder constructs a Builder for the internal pool.
	NewBuilder func() Builder
}

// DefaultCacheConfig returns production-friendly defaults.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Capacity: 2048,
		TTL:      10 * time.Minute,
	}
}

func (c CacheConfig) withDefaults() CacheConfig {
	if c.Capacity <= 0 {
		c.Capacity = 1000
	}
	if c.MaxMemory < 0 {
		c.MaxMemory = 0
	}
	if c.TTL < 0 {
		c.TTL = 0
	}
	if c.NewBuilder == nil {
		c.NewBuilder = func() Builder { return NewCFGBuilder() }
	}
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

// cacheKey is a 128-bit content hash of a BuildInput.
type cacheKey struct{ hi, lo uint64 }

type entry struct {
	key       cacheKey
	cfg       *ControlFlowGraph
	class     string
	expiresAt time.Time // zero ⇒ never expires
	size      int64     // estimated bytes
}

func (e *entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// call is an in-flight build shared between a leader and its waiters.
type call struct {
	wg  sync.WaitGroup
	cfg *ControlFlowGraph
}

type counters struct {
	hits        atomic.Int64
	misses      atomic.Int64
	coalesced   atomic.Int64 // misses that piggy-backed on an in-flight build
	evictions   atomic.Int64 // removed due to capacity / memory pressure
	expirations atomic.Int64 // removed due to TTL
	builds      atomic.Int64
	buildNanos  atomic.Int64
}

type shard struct {
	mu       sync.Mutex
	items    map[cacheKey]*list.Element
	lru      *list.List // front = most recently used
	inflight map[cacheKey]*call
	memBytes int64
	capacity int
	// globalCapacity is the cache-wide entry limit. A per-shard split can
	// evict early when hashing is uneven, so eviction must use the shared
	// global count instead.
	globalCapacity int
	size           *atomic.Int64
	maxMem         int64
	stats          *counters

	_ [cacheLine]byte // keep neighbouring shards off this cache line
}

// CFGCache is a concurrent, sharded LRU cache for Control Flow Graphs.
type CFGCache struct {
	shards   [numShards]shard
	capacity atomic.Int64
	size     atomic.Int64
	maxMem   int64
	ttl      time.Duration
	seed     maphash.Seed
	builders sync.Pool
	stats    counters
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

// NewCFGCache creates a cache with the given capacity and no TTL.
func NewCFGCache(capacity int) *CFGCache {
	return NewCFGCacheWithConfig(CacheConfig{Capacity: capacity})
}

// NewCFGCacheWithConfig creates a fully configured cache.
func NewCFGCacheWithConfig(cfg CacheConfig) *CFGCache {
	cfg = cfg.withDefaults()

	c := &CFGCache{
		maxMem: cfg.MaxMemory,
		ttl:    cfg.TTL,
		seed:   maphash.MakeSeed(),
	}
	c.capacity.Store(int64(cfg.Capacity))
	c.builders.New = func() any { return cfg.NewBuilder() }

	perShard, perShardMem := splitBudget(cfg.Capacity, cfg.MaxMemory)
	for i := range c.shards {
		s := &c.shards[i]
		s.items = make(map[cacheKey]*list.Element, perShard)
		s.lru = list.New()
		s.inflight = make(map[cacheKey]*call)
		s.capacity = perShard
		s.globalCapacity = cfg.Capacity
		s.size = &c.size
		s.maxMem = perShardMem
		s.stats = &c.stats
	}
	return c
}

// splitBudget divides global limits across shards, rounding up so the
// aggregate never falls below what the caller asked for.
func splitBudget(capacity int, maxMem int64) (int, int64) {
	perShard := max((capacity+numShards-1)/numShards, 1)
	var perShardMem int64
	if maxMem > 0 {
		perShardMem = max((maxMem+numShards-1)/numShards, 1)
	}
	return perShard, perShardMem
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// GetOrBuild returns the cached CFG for input, building it on a miss.
//
// Concurrent misses for the same input are coalesced: one goroutine builds,
// the rest wait and share the result. If the builder panics, the panic
// propagates to the leader and waiters receive nil.
func (c *CFGCache) GetOrBuild(in BuildInput) *ControlFlowGraph {
	key := c.keyOf(in)
	s := c.shardFor(key)

	s.mu.Lock()
	if cfg, ok := s.get(key, time.Now()); ok {
		s.mu.Unlock()
		c.stats.hits.Add(1)
		return cfg
	}
	if cl, ok := s.inflight[key]; ok {
		s.mu.Unlock()
		c.stats.coalesced.Add(1)
		cl.wg.Wait()
		return cl.cfg
	}
	cl := &call{}
	cl.wg.Add(1)
	s.inflight[key] = cl
	s.mu.Unlock()

	c.stats.misses.Add(1)

	// The deferred block runs even if the builder panics — waiters must
	// never be left hanging and the inflight slot must always be released.
	var cfg *ControlFlowGraph
	defer func() {
		cl.cfg = cfg
		s.mu.Lock()
		delete(s.inflight, key)
		if cfg != nil {
			s.put(c.newEntry(key, in.ClassName, cfg))
		}
		s.mu.Unlock()
		cl.wg.Done()
	}()

	cfg = c.build(in)
	return cfg
}

// Get returns the cached CFG for input without building. Returns nil on miss.
func (c *CFGCache) Get(in BuildInput) *ControlFlowGraph {
	key := c.keyOf(in)
	s := c.shardFor(key)

	s.mu.Lock()
	cfg, ok := s.get(key, time.Now())
	s.mu.Unlock()

	if ok {
		c.stats.hits.Add(1)
	} else {
		c.stats.misses.Add(1)
	}
	return cfg
}

// Invalidate removes the entry for input, if present. Reports whether it existed.
func (c *CFGCache) Invalidate(in BuildInput) bool {
	key := c.keyOf(in)
	s := c.shardFor(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.items[key]
	if ok {
		s.remove(el)
	}
	return ok
}

// InvalidateClass removes every entry belonging to className.
// Returns the number of removed entries. O(total entries).
func (c *CFGCache) InvalidateClass(className string) int {
	return c.removeIf(func(e *entry) bool { return e.class == className })
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

// Clear drops every entry. In-flight builds are unaffected.
func (c *CFGCache) Clear() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.items = make(map[cacheKey]*list.Element, s.capacity)
		s.lru.Init()
		s.memBytes = 0
		s.mu.Unlock()
	}
	c.size.Store(0)
}

// EvictExpired proactively removes TTL-expired entries and returns their count.
func (c *CFGCache) EvictExpired() int {
	if c.ttl == 0 {
		return 0
	}
	now := time.Now()
	n := c.removeIf(func(e *entry) bool { return e.expired(now) })
	c.stats.expirations.Add(int64(n))
	return n
}

// RunJanitor calls EvictExpired every interval until ctx is cancelled.
// It blocks; run it in its own goroutine.
func (c *CFGCache) RunJanitor(ctx context.Context, interval time.Duration) {
	if c.ttl == 0 || interval <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.EvictExpired()
		}
	}
}

// Resize changes the entry capacity, evicting LRU entries if shrinking.
func (c *CFGCache) Resize(capacity int) {
	capacity = max(capacity, 1)
	c.capacity.Store(int64(capacity))

	perShard, _ := splitBudget(capacity, 0)
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.capacity = perShard
		s.globalCapacity = capacity
		s.trim()
		s.mu.Unlock()
	}
}

// Warm populates the cache sequentially.
func (c *CFGCache) Warm(inputs []BuildInput) {
	for i := range inputs {
		c.GetOrBuild(inputs[i])
	}
}

// WarmParallel populates the cache using up to workers goroutines.
// Duplicate inputs are naturally deduplicated by singleflight.
func (c *CFGCache) WarmParallel(inputs []BuildInput, workers int) {
	n := int64(len(inputs))
	if n == 0 {
		return
	}
	workers = min(max(workers, 1), int(n))
	if workers == 1 {
		c.Warm(inputs)
		return
	}

	var (
		next atomic.Int64
		wg   sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := next.Add(1) - 1
				if i >= n {
					return
				}
				c.GetOrBuild(inputs[i])
			}
		}()
	}
	wg.Wait()
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

// CacheStats is a point-in-time snapshot of cache metrics.
type CacheStats struct {
	Hits        int64
	Misses      int64
	Coalesced   int64 // misses served by an in-flight build
	Evictions   int64
	Expirations int64
	Builds      int64
	AvgBuild    time.Duration

	Size        int
	Capacity    int
	MemoryBytes int64
	HitRate     float64 // hits / (hits + misses + coalesced)
}

// String renders a compact single-line summary — handy for logs.
func (s CacheStats) String() string {
	return fmt.Sprintf(
		"cfgcache size=%d/%d mem=%.1fMiB hit=%.1f%% hits=%d misses=%d coalesced=%d builds=%d avg=%s evicted=%d expired=%d",
		s.Size, s.Capacity, float64(s.MemoryBytes)/(1<<20), s.HitRate*100,
		s.Hits, s.Misses, s.Coalesced, s.Builds, s.AvgBuild.Round(time.Microsecond),
		s.Evictions, s.Expirations,
	)
}

// Stats returns a snapshot of the cache metrics. O(shards).
func (c *CFGCache) Stats() CacheStats {
	st := CacheStats{
		Hits:        c.stats.hits.Load(),
		Misses:      c.stats.misses.Load(),
		Coalesced:   c.stats.coalesced.Load(),
		Evictions:   c.stats.evictions.Load(),
		Expirations: c.stats.expirations.Load(),
		Builds:      c.stats.builds.Load(),
		Capacity:    c.Capacity(),
	}

	if st.Builds > 0 {
		st.AvgBuild = time.Duration(c.stats.buildNanos.Load() / st.Builds)
	}
	if total := st.Hits + st.Misses + st.Coalesced; total > 0 {
		st.HitRate = float64(st.Hits) / float64(total)
	}

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		st.Size += s.lru.Len()
		st.MemoryBytes += s.memBytes
		s.mu.Unlock()
	}
	return st
}

// Len returns the current number of entries.
func (c *CFGCache) Len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += s.lru.Len()
		s.mu.Unlock()
	}
	return n
}

// Size is an alias for Len, kept for API compatibility.
func (c *CFGCache) Size() int { return c.Len() }

// Capacity returns the configured entry limit.
func (c *CFGCache) Capacity() int { return int(c.capacity.Load()) }

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNALS
// ═══════════════════════════════════════════════════════════════════════════════

func (c *CFGCache) shardFor(k cacheKey) *shard {
	return &c.shards[(k.hi>>(64-shardBits))&shardMask]
}

func (c *CFGCache) build(in BuildInput) *ControlFlowGraph {
	b := c.builders.Get().(Builder)
	// Deliberately not deferred: a builder that panicked may be corrupt
	// and must not return to the pool.
	start := time.Now()
	cfg := b.Build(in)
	c.stats.buildNanos.Add(int64(time.Since(start)))
	c.stats.builds.Add(1)
	c.builders.Put(b)
	return cfg
}

func (c *CFGCache) newEntry(key cacheKey, class string, cfg *ControlFlowGraph) *entry {
	e := &entry{key: key, cfg: cfg, class: class, size: estimateCFGMemory(cfg)}
	if c.ttl > 0 {
		e.expiresAt = time.Now().Add(c.ttl)
	}
	return e
}

// removeIf deletes every entry matching pred across all shards.
func (c *CFGCache) removeIf(pred func(*entry) bool) int {
	removed := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for el := s.lru.Front(); el != nil; {
			next := el.Next()
			if pred(el.Value.(*entry)) {
				s.remove(el)
				removed++
			}
			el = next
		}
		s.mu.Unlock()
	}
	return removed
}

// ── shard (all methods require s.mu held) ────────────────────────────────────

func (s *shard) get(key cacheKey, now time.Time) (*ControlFlowGraph, bool) {
	el, ok := s.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if e.expired(now) {
		s.remove(el)
		s.stats.expirations.Add(1)
		return nil, false
	}
	s.lru.MoveToFront(el)
	return e.cfg, true
}

func (s *shard) put(e *entry) {
	if old, ok := s.items[e.key]; ok {
		s.remove(old)
	}
	s.items[e.key] = s.lru.PushFront(e)
	s.memBytes += e.size
	s.size.Add(1)
	s.trim()
}

func (s *shard) remove(el *list.Element) {
	e := s.lru.Remove(el).(*entry)
	delete(s.items, e.key)
	s.memBytes -= e.size
	s.size.Add(-1)
}

// trim enforces both the count and the byte budget, LRU-first.
// An entry larger than the whole budget is inserted and immediately
// evicted — by design, such monsters are not worth caching.
func (s *shard) trim() {
	for s.lru.Len() > 0 && s.overBudget() {
		s.remove(s.lru.Back())
		s.stats.evictions.Add(1)
	}
}

func (s *shard) overBudget() bool {
	return s.size.Load() > int64(s.globalCapacity) || (s.maxMem > 0 && s.memBytes > s.maxMem)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASHING — 128-bit, zero-alloc, length-prefixed
// ═══════════════════════════════════════════════════════════════════════════════

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// keyHasher feeds the same byte stream into two independent hash functions.
// maphash is AES-accelerated on amd64/arm64; FNV-1a is the cheap second half
// that turns "unlikely collision" into "not in this universe".
type keyHasher struct {
	mh  maphash.Hash
	fnv uint64
	buf [4]byte
}

func (h *keyHasher) init(seed maphash.Seed) {
	h.mh.SetSeed(seed)
	h.fnv = fnvOffset64
}

func (h *keyHasher) str(s string) {
	h.u32(uint32(len(s)))
	h.mh.WriteString(s)
	f := h.fnv
	for i := 0; i < len(s); i++ {
		f ^= uint64(s[i])
		f *= fnvPrime64
	}
	h.fnv = f
}

func (h *keyHasher) u32(v uint32) {
	binary.LittleEndian.PutUint32(h.buf[:], v)
	h.mh.Write(h.buf[:])
	f := h.fnv
	for _, b := range h.buf {
		f ^= uint64(b)
		f *= fnvPrime64
	}
	h.fnv = f
}

func (h *keyHasher) sum() cacheKey {
	return cacheKey{hi: h.mh.Sum64(), lo: h.fnv}
}

func (c *CFGCache) keyOf(in BuildInput) cacheKey {
	var h keyHasher
	h.init(c.seed)

	h.str(in.ClassName)
	h.str(in.MethodName)
	h.str(in.Signature)

	h.u32(uint32(len(in.Instructions)))
	for _, ins := range in.Instructions {
		h.str(ins.Raw)
	}

	h.u32(uint32(len(in.Labels)))
	for _, l := range in.Labels {
		h.str(l.Name)
	}

	h.u32(uint32(len(in.TryBlocks)))
	for _, tb := range in.TryBlocks {
		h.u32(uint32(tb.StartIdx))
		h.u32(uint32(tb.EndIdx))
		h.u32(uint32(len(tb.Handlers)))
		for _, hd := range tb.Handlers {
			h.str(hd.Type)
			h.u32(uint32(hd.HandlerIdx))
		}
	}

	return h.sum()
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY ESTIMATION
// ═══════════════════════════════════════════════════════════════════════════════

// Rough per-object footprints. Tune against pprof for your ControlFlowGraph shape.
const (
	memBaseCFG     = 256
	memPerNode     = 200
	memPerEdge     = 80
	memPerInstrRef = 40
)

func estimateCFGMemory(cfg *ControlFlowGraph) int64 {
	if cfg == nil {
		return 0
	}
	mem := int64(memBaseCFG)
	mem += int64(len(cfg.Nodes)) * memPerNode
	mem += int64(len(cfg.Edges)) * memPerEdge
	for _, n := range cfg.Nodes {
		mem += int64(len(n.Instructions)) * memPerInstrRef
	}
	return mem
}
