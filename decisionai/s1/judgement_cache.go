package s1

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
)

const DefaultJudgementCacheBytes int64 = 2 << 20

// Hash, verdict, LRU node, map slot and allocator overhead. No input strings
// are retained. The allowance deliberately exceeds the payload's 56 bytes.
const judgementCacheEntryBytes int64 = 192

// CachedBackend reuses complete pair judgements from one immutable backend.
// Configure model weights and scoring settings before wrapping it. If those
// settings change between requests, call ClearCache or create a new wrapper.
type CachedBackend struct {
	backend    Backend
	mu         sync.Mutex
	cache      weightedCache[[32]byte, Judgement]
	generation uint64
	calls      atomic.Int64
	hits       atomic.Int64
}

func NewCachedBackend(backend Backend, bytes int64) *CachedBackend {
	return &CachedBackend{backend: backend, cache: weightedCache[[32]byte, Judgement]{limit: max(0, bytes)}}
}

func (b *CachedBackend) Name() string               { return b.backend.Name() }
func (b *CachedBackend) Tokens(s string) int        { return b.backend.Tokens(s) }
func (b *CachedBackend) Stats() (calls, hits int64) { return b.calls.Load(), b.hits.Load() }

func (b *CachedBackend) CacheUsage() CacheUsage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cache.usage()
}

func (b *CachedBackend) SetCacheLimit(bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cache.resize(bytes)
}

// ClearCache also prevents requests already in flight from refilling the cache
// with results computed before this invalidation. Lifetime counters are kept.
func (b *CachedBackend) ClearCache() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.generation++
	b.cache = weightedCache[[32]byte, Judgement]{limit: b.cache.limit}
}

func judgementKey(p Pair) [32]byte {
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[:8], uint64(len(p.Premise)))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(len(p.Hypothesis)))
	h := sha256.New()
	h.Write(lengths[:])
	h.Write([]byte(p.Premise))
	h.Write([]byte(p.Hypothesis))
	var key [32]byte
	h.Sum(key[:0])
	return key
}

func (b *CachedBackend) JudgeBatch(pairs []Pair) []Judgement {
	out, err := b.JudgeBatchContext(context.Background(), pairs)
	if err != nil {
		// Backend has no error return. Never turn a failed inference into a
		// plausible verdict; Engine uses JudgeBatchContext and returns errors.
		panic(err)
	}
	return out
}

func (b *CachedBackend) JudgeBatchContext(ctx context.Context, pairs []Pair) ([]Judgement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]Judgement, len(pairs))
	keys := make([][32]byte, len(pairs))
	for i, p := range pairs {
		keys[i] = judgementKey(p)
	}
	var todo []Pair
	var todoKeys [][32]byte
	positions := make([]int, len(pairs))
	pending := make(map[[32]byte]int)
	var hits int64
	b.mu.Lock()
	generation := b.generation
	for i, key := range keys {
		if j, ok := b.cache.get(key); ok {
			out[i], positions[i] = j, -1
			hits++
		} else if pos, ok := pending[key]; ok {
			positions[i] = pos
			hits++
		} else {
			positions[i], pending[key] = len(todo), len(todo)
			todo = append(todo, pairs[i])
			todoKeys = append(todoKeys, key)
		}
	}
	b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.hits.Add(hits)
	if len(todo) == 0 {
		return out, nil
	}
	b.calls.Add(int64(len(todo)))
	js, err := judge(ctx, b.backend, todo)
	if err != nil {
		return nil, err
	}
	if len(js) != len(todo) {
		return nil, fmt.Errorf("%s: returned %d judgements for %d pairs", b.Name(), len(js), len(todo))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	if generation == b.generation {
		for i, key := range todoKeys {
			b.cache.put(key, js[i], judgementCacheEntryBytes)
		}
	}
	b.mu.Unlock()
	for i, pos := range positions {
		if pos >= 0 {
			out[i] = js[pos]
		}
	}
	return out, nil
}
