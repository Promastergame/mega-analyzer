package s1

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

type cacheTestBackend struct {
	fn    func(context.Context, []Pair) ([]Judgement, error)
	count atomic.Int64
}

func (b *cacheTestBackend) Name() string        { return "cache-test" }
func (b *cacheTestBackend) Tokens(s string) int { return len(s) }
func (b *cacheTestBackend) JudgeBatch(ps []Pair) []Judgement {
	js, err := b.JudgeBatchContext(context.Background(), ps)
	if err != nil {
		panic(err)
	}
	return js
}
func (b *cacheTestBackend) JudgeBatchContext(ctx context.Context, ps []Pair) ([]Judgement, error) {
	b.count.Add(int64(len(ps)))
	if b.fn != nil {
		return b.fn(ctx, ps)
	}
	return LexicalBackend{}.JudgeBatch(ps), nil
}

func TestJudgementCacheOrderDedupAndIsolation(t *testing.T) {
	raw := &cacheTestBackend{}
	c := NewCachedBackend(raw, 2*judgementCacheEntryBytes)
	a, b, d := Pair{"a b", "a"}, Pair{"c d", "d"}, Pair{"e f", "e"}
	ps := []Pair{a, b, a, b}
	want := LexicalBackend{}.JudgeBatch(ps)
	if got := c.JudgeBatch(ps); !reflect.DeepEqual(got, want) || raw.count.Load() != 2 {
		t.Fatalf("duplicates/order: got %v, calls %d", got, raw.count.Load())
	}
	c.JudgeBatch([]Pair{a}) // a is hotter than b
	c.JudgeBatch([]Pair{d}) // evict b
	c.JudgeBatch([]Pair{a})
	if raw.count.Load() != 3 {
		t.Fatal("recently used entry was evicted")
	}
	c.JudgeBatch([]Pair{b})
	if raw.count.Load() != 4 {
		t.Fatal("least recently used entry was not evicted")
	}
	if u := c.CacheUsage(); u.Bytes > u.LimitBytes || u.Entries != 2 {
		t.Fatal(u)
	}
	other := NewCachedBackend(raw, judgementCacheEntryBytes)
	other.JudgeBatch([]Pair{b})
	if raw.count.Load() != 5 {
		t.Fatal("two backends shared cached judgements")
	}
	c.ClearCache()
	c.JudgeBatch([]Pair{b})
	if raw.count.Load() != 6 {
		t.Fatal("cache invalidation did not take effect")
	}
	c.SetCacheLimit(0)
	c.JudgeBatch([]Pair{b})
	c.JudgeBatch([]Pair{b})
	if raw.count.Load() != 8 || c.CacheUsage().Entries != 0 {
		t.Fatal("cache was not disabled")
	}
}

func TestJudgementKeyEmbeddedSeparators(t *testing.T) {
	a := Pair{"x\x00y", "z"}
	b := Pair{"x", "y\x00z"}
	if judgementKey(a) == judgementKey(b) || judgementKey(a) == judgementKey(Pair{a.Hypothesis, a.Premise}) {
		t.Fatal("distinct pairs share a key")
	}
}

func TestJudgementCacheDoesNotRetainFailedBatches(t *testing.T) {
	boom := errors.New("inference failed")
	for _, mode := range []string{"error", "short", "long", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw := &cacheTestBackend{fn: func(context.Context, []Pair) ([]Judgement, error) {
				switch mode {
				case "error":
					return nil, boom
				case "short":
					return nil, nil
				case "long":
					return make([]Judgement, 2), nil
				default:
					cancel()
					return make([]Judgement, 1), nil
				}
			}}
			c := NewCachedBackend(raw, DefaultJudgementCacheBytes)
			ps := []Pair{{"premise", "hypothesis"}}
			if _, err := c.JudgeBatchContext(ctx, ps); err == nil || c.CacheUsage().Entries != 0 {
				t.Fatalf("failed batch was accepted: %v", err)
			}
			raw.fn = nil
			if _, err := c.JudgeBatchContext(context.Background(), ps); err != nil || c.CacheUsage().Entries != 1 {
				t.Fatalf("retry failed: %v", err)
			}
		})
	}
}

func TestJudgementCacheCanceledHitAndInFlightInvalidation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	raw := &cacheTestBackend{fn: func(context.Context, []Pair) ([]Judgement, error) {
		close(entered)
		<-release
		return []Judgement{{Entail: 1}}, nil
	}}
	c := NewCachedBackend(raw, DefaultJudgementCacheBytes)
	ps := []Pair{{"a", "a"}}
	done := make(chan struct{})
	go func() { defer close(done); c.JudgeBatch(ps) }()
	<-entered
	c.ClearCache()
	close(release)
	<-done
	if c.CacheUsage().Entries != 0 {
		t.Fatal("invalidated in-flight result refilled the cache")
	}
	raw.fn = nil
	c.JudgeBatch(ps)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.JudgeBatchContext(ctx, ps); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cache hit returned success: %v", err)
	}
}

func TestJudgementCacheConcurrentRequests(t *testing.T) {
	c := NewCachedBackend(&cacheTestBackend{}, 4*judgementCacheEntryBytes)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ps := []Pair{{"alpha beta", "alpha"}, {"delta gamma", "delta"}}
			want := LexicalBackend{}.JudgeBatch(ps)
			for j := 0; j < 30; j++ {
				if got := c.JudgeBatch(ps); !reflect.DeepEqual(got, want) {
					t.Error("concurrent answer changed")
				}
				if j%10 == 0 {
					c.ClearCache()
					c.SetCacheLimit(4 * judgementCacheEntryBytes)
				}
			}
		}()
	}
	wg.Wait()
	if u := c.CacheUsage(); u.Bytes > u.LimitBytes {
		t.Fatal(u)
	}
}
