package s1

import (
	"context"
	"strings"
	"testing"
)

func TestTokenWindowsOversizedWord(t *testing.T) {
	count := func(s string) int { return len([]rune(s)) + 2 }
	text := strings.Repeat("я", 301)
	windows := tokenWindows(text, 32, count)
	if len(windows) < 2 {
		t.Fatal("long word was not split")
	}
	var rebuilt string
	for _, w := range windows {
		if count(w) > 32 {
			t.Fatalf("oversize %d", count(w))
		}
		rebuilt += w
	}
	if rebuilt != text {
		t.Fatal("word tail lost or duplicated")
	}
}
func TestRetrievalExactTermsDistinguishStemCollision(t *testing.T) {
	a, b := retrievalTerms("invoiceABC 7"), retrievalTerms("invoiceXYZ 8")
	if a["exact:invoiceabc"] == 0 || b["exact:invoicexyz"] == 0 || a["exact:7"] == 0 {
		t.Fatal("exact terms or single digit lost")
	}
	if a["exact:invoicexyz"] != 0 {
		t.Fatal("stem collision overwrote exact token")
	}
}
func TestContextIndexBoundedSharedAndCancelled(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	state := strings.Repeat("Document about orchards and fruit. ", 50)
	index, err := e.contextIndexFor(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	copyEngine := *e
	again, err := copyEngine.contextIndexFor(context.Background(), state)
	if err != nil || index != again {
		t.Fatal("engine copies did not share immutable index")
	}
	usage := e.ContextCacheUsage()
	if usage.Entries != 1 {
		t.Fatalf("cache not filled: %+v", usage)
	}
	e.SetContextCacheLimit(64)
	if e.ContextCacheUsage().Entries != 0 {
		t.Fatal("oversized index survived resize")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := e.contextChunksContext(ctx, state, nil); err != context.Canceled {
		t.Fatal(err)
	}
}
func BenchmarkContextIndexCached(b *testing.B) {
	e := NewEngine(fake{}, DefaultCalibration())
	state := strings.Repeat("Orchard fruit and named entities. ", 200)
	e.contextIndexFor(context.Background(), state)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.contextIndexFor(context.Background(), state)
	}
}
func BenchmarkContextIndexUncached(b *testing.B) {
	e := NewEngine(fake{}, DefaultCalibration())
	e.SetContextCacheLimit(0)
	state := strings.Repeat("Orchard fruit and named entities. ", 200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.contextIndexFor(context.Background(), state)
	}
}
