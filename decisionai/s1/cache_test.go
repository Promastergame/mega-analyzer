package s1

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"decisionai/semai"
)

func TestWeightedCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := weightedCache[string, int]{limit: 30}
	for i, key := range []string{"a", "b", "c"} {
		c.put(key, i, 10)
	}
	c.get("a")
	c.put("d", 4, 10)
	if _, ok := c.get("b"); ok {
		t.Fatal("least recently used entry survived")
	}
	for _, key := range []string{"a", "c", "d"} {
		if _, ok := c.get(key); !ok {
			t.Fatalf("useful entry %q was flushed", key)
		}
	}
	if c.put("oversized", 5, 31) || len(c.items) != 3 {
		t.Fatal("oversized insertion disturbed the cache")
	}
	c.put("a", 6, 20)
	if got, _ := c.get("a"); got != 6 || c.bytes > c.limit {
		t.Fatal("replacement exceeded the budget or retained an old value")
	}
	c.resize(10)
	if c.bytes > 10 {
		t.Fatal("resizing did not enforce the budget")
	}
	c.resize(0)
	if c.bytes != 0 || len(c.items) != 0 || c.put("off", 1, 1) {
		t.Fatal("disabled cache retained data")
	}
}

func TestEncodingCacheBoundsAndConcurrentReuse(t *testing.T) {
	path := "../models/s1-distilled.dte"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("real weights unavailable")
	}
	enc, err := semai.LoadEncoder(path)
	if err != nil {
		t.Fatal(err)
	}
	b := NewEmbedBackend(enc)
	b.SetCacheLimit(96 << 10)
	text := "A short request with a stable encoding."
	first := b.get(text)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if b.get(text) != first {
					t.Error("concurrent reader did not reuse the cached encoding")
				}
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 12; i++ {
		b.get(fmt.Sprintf("A different request number %d.", i))
		if u := b.CacheUsage(); u.Bytes > u.LimitBytes {
			t.Fatalf("cache exceeds its budget: %+v", u)
		}
	}
	// Oversized encodings are computed but do not evict a hot, smaller entry.
	hot := b.get(text)
	u := b.CacheUsage()
	b.get(strings.Repeat("A much longer request. ", 80))
	if after := b.CacheUsage(); after != u || b.get(text) != hot {
		t.Fatalf("oversized entry flushed cached vectors: before=%+v after=%+v", u, after)
	}
	b.SetCacheLimit(0)
	if b.get(text) == b.get(text) || b.CacheUsage().Bytes != 0 {
		t.Fatal("zero budget must disable retention")
	}
}
