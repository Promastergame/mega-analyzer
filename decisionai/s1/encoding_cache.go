package s1

import (
	"strings"

	"decisionai/semai"
)

// DefaultEncodingCacheBytes bounds the cache for each EmbedBackend. Model
// weights and temporary inference buffers are separate from this budget.
const DefaultEncodingCacheBytes int64 = 16 << 20

type encodingFlight struct {
	done  chan struct{}
	value *semai.Encoding
}

// SetCacheLimit changes the encoding-cache budget; zero disables retention.
// Concurrent encodes finish normally and use the new budget when inserting.
func (b *EmbedBackend) SetCacheLimit(bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cache.resize(bytes)
}

func (b *EmbedBackend) CacheUsage() CacheUsage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cache.usage()
}

// encodingBytes counts retained arrays, the copied key, slice headers, and
// conservative map/node and allocator overhead. Piece strings are shared with
// the model's immutable vocabulary and need no additional backing storage.
func encodingBytes(text string, e *semai.Encoding) int64 {
	n := int64(256 + len(text) + cap(e.Pieces)*16 + cap(e.Tokens)*24)
	n += int64(cap(e.CLS)+cap(e.Mean)) * 4
	for _, token := range e.Tokens {
		n += int64(cap(token))*4 + 32
	}
	return n
}

func (b *EmbedBackend) get(text string) *semai.Encoding {
	b.mu.Lock()
	if e, ok := b.cache.get(text); ok {
		b.mu.Unlock()
		return e
	}
	if flight, ok := b.busy[text]; ok {
		b.mu.Unlock()
		<-flight.done
		// Share the result even when it is too large to retain in the cache.
		return flight.value
	}
	flight := &encodingFlight{done: make(chan struct{})}
	if b.busy == nil {
		b.busy = make(map[string]*encodingFlight)
	}
	b.busy[text] = flight
	b.mu.Unlock()

	e := b.enc.Encode(text)
	cost := encodingBytes(text, e)
	b.mu.Lock()
	if cost <= b.cache.limit {
		// A chunk may be a substring of a much larger request. Retain only the
		// bytes counted by the cache instead of its entire backing string.
		b.cache.put(strings.Clone(text), e, cost)
	}
	flight.value = e
	delete(b.busy, text)
	close(flight.done)
	b.mu.Unlock()
	return e
}
