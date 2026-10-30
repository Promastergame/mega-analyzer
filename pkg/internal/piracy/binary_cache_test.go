// Package piracy — binary_cache_test.go
// Тесты для binary_analysis.go и cache.go — прицельное покрытие
package piracy

import (
	"bytes"
	"context"
	"crypto/rand"
	"math"
	"sync"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACT STRINGS
// ═══════════════════════════════════════════════════════════════════════════════

func TestExtractStrings_Basic(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		minLen int
		want   []string
	}{
		{
			name:   "simple ASCII",
			data:   []byte("hello world"),
			minLen: 4,
			want:   []string{"hello world"},
		},
		{
			name:   "separated by nulls",
			data:   []byte("hello\x00\x00world\x00\x00test"),
			minLen: 4,
			want:   []string{"hello", "world"},
			// "test" is only 4 chars, should be included with minLen=4
		},
		{
			name:   "short strings filtered",
			data:   []byte("ab\x00cd\x00longstring"),
			minLen: 6,
			want:   []string{"longstring"},
		},
		{
			name:   "empty data",
			data:   []byte{},
			minLen: 4,
			want:   nil,
		},
		{
			name:   "all binary",
			data:   []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			minLen: 4,
			want:   nil,
		},
		{
			name:   "minLen clamped to 4",
			data:   []byte("ab\x00cdef"),
			minLen: 1, // should be clamped to 4
			want:   []string{"cdef"},
		},
		{
			name:   "last chunk included",
			data:   []byte("\x00\x00longstring"),
			minLen: 4,
			want:   []string{"longstring"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractStrings(tt.data, tt.minLen)

			if tt.want == nil {
				if len(got) != 0 {
					t.Errorf("expected no strings, got %v", got)
				}
				return
			}

			// Проверяем что все ожидаемые строки присутствуют
			for _, w := range tt.want {
				found := false
				for _, g := range got {
					if g == w {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected string %q not found in %v", w, got)
				}
			}
		})
	}
}

func TestExtractStrings_LargeInput(t *testing.T) {
	// 1MB of "A" with embedded strings
	data := bytes.Repeat([]byte{0x00}, 1024*1024)
	copy(data[1000:], []byte("secret_password"))
	copy(data[500000:], []byte("another_string_here"))

	strings := ExtractStrings(data, 6)

	if len(strings) < 2 {
		t.Errorf("expected at least 2 strings, got %d", len(strings))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isPrintable
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		r    rune
		want bool
	}{
		{'A', true},
		{'z', true},
		{' ', true},
		{'~', true},
		{'\n', false},
		{'\t', false},
		{0x00, false},
		{0x7F, false}, // DEL
		{'日', true},   // unicode printable
	}

	for _, tt := range tests {
		got := isPrintable(tt.r)
		if got != tt.want {
			t.Errorf("isPrintable(%q) = %v, want %v", tt.r, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateEntropy_Patterns(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		minE float64
		maxE float64
	}{
		{
			name: "empty",
			data: []byte{},
			minE: 0, maxE: 0,
		},
		{
			name: "single byte repeated",
			data: bytes.Repeat([]byte{0xAA}, 1000),
			minE: 0, maxE: 0.01,
		},
		{
			name: "two bytes equal",
			data: bytes.Repeat([]byte{0x00, 0xFF}, 500),
			minE: 0.99, maxE: 1.01,
		},
		{
			name: "normal text",
			data: []byte("The quick brown fox jumps over the lazy dog"),
			minE: 3.0, maxE: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := CalculateEntropy(tt.data)
			if e < tt.minE || e > tt.maxE {
				t.Errorf("entropy = %f, want [%f, %f]", e, tt.minE, tt.maxE)
			}
		})
	}
}

func TestCalculateEntropy_RandomDataHighEntropy(t *testing.T) {
	data := make([]byte, 10000)
	_, _ = rand.Read(data)

	e := CalculateEntropy(data)
	// Random data should have entropy close to 8.0
	if e < 7.5 {
		t.Errorf("random data entropy = %f, expected > 7.5", e)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// IS LIKELY ENCRYPTED
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsLikelyEncrypted(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "too short",
			data: []byte("short"),
			want: false,
		},
		{
			name: "normal text",
			data: bytes.Repeat([]byte("hello world "), 100),
			want: false,
		},
		{
			name: "repeated bytes",
			data: bytes.Repeat([]byte{0x42}, 1000),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLikelyEncrypted(tt.data)
			if got != tt.want {
				t.Errorf("IsLikelyEncrypted() = %v, want %v", got, tt.want)
			}
		})
	}

	// Random data — should be "encrypted"
	t.Run("random data", func(t *testing.T) {
		data := make([]byte, 10000)
		_, _ = rand.Read(data)
		if !IsLikelyEncrypted(data) {
			e := CalculateEntropy(data)
			t.Errorf("random data should look encrypted, entropy = %f", e)
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE — основные операции
// ═══════════════════════════════════════════════════════════════════════════════

func TestCache_SetGet(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)
	defer cache.Clear()

	content := []byte("test content")
	result := &Result{IsPirated: true, Confidence: 0.9}

	// Miss
	_, ok := cache.Get(content, 1)
	if ok {
		t.Error("expected cache miss")
	}

	// Set
	cache.Set(content, result, 1)

	// Hit
	got, ok := cache.Get(content, 1)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Confidence != 0.9 {
		t.Errorf("confidence = %f, want 0.9", got.Confidence)
	}
}

func TestCache_ConfigVersionInvalidation(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)
	defer cache.Clear()

	content := []byte("test")
	result := &Result{IsPirated: true}

	cache.Set(content, result, 1)

	// Same version → hit
	_, ok := cache.Get(content, 1)
	if !ok {
		t.Error("expected hit with same config version")
	}

	// Different version → miss (invalidated)
	_, ok = cache.Get(content, 2)
	if ok {
		t.Error("expected miss with different config version")
	}
}

func TestCache_TTLExpiration(t *testing.T) {
	cache := NewResultCache(100, 50*time.Millisecond)
	defer cache.Clear()

	content := []byte("ttl test")
	result := &Result{IsPirated: false}

	cache.Set(content, result, 1)

	// Immediate hit
	_, ok := cache.Get(content, 1)
	if !ok {
		t.Error("expected immediate hit")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Expired → miss
	_, ok = cache.Get(content, 1)
	if ok {
		t.Error("expected miss after TTL expiration")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	cache := NewResultCache(3, 10*time.Minute)
	defer cache.Clear()

	// Fill cache: items 1, 2, 3
	for i := 0; i < 3; i++ {
		content := []byte{byte(i)}
		cache.Set(content, &Result{Confidence: float64(i)}, 1)
	}

	// Add item 4 → should evict item 1 (oldest)
	cache.Set([]byte{3}, &Result{Confidence: 3}, 1)

	// Item 0 should be evicted
	_, ok := cache.Get([]byte{0}, 1)
	if ok {
		t.Error("expected item 0 to be evicted")
	}

	// Item 2 should still be there
	_, ok = cache.Get([]byte{2}, 1)
	if !ok {
		t.Error("expected item 2 to still be cached")
	}
}

func TestCache_UpdateExisting(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)
	defer cache.Clear()

	content := []byte("update me")

	cache.Set(content, &Result{Confidence: 0.5}, 1)
	cache.Set(content, &Result{Confidence: 0.9}, 1)

	got, ok := cache.Get(content, 1)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Confidence != 0.9 {
		t.Errorf("expected updated confidence 0.9, got %f", got.Confidence)
	}
}

func TestCache_Stats(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)
	defer cache.Clear()

	content := []byte("stats test")
	cache.Set(content, &Result{}, 1)

	// 1 hit
	cache.Get(content, 1)
	// 2 misses
	cache.Get([]byte("miss1"), 1)
	cache.Get([]byte("miss2"), 1)

	hits, misses, hitRate := cache.Stats()
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	if misses != 2 {
		t.Errorf("misses = %d, want 2", misses)
	}

	expectedRate := 1.0 / 3.0
	if math.Abs(hitRate-expectedRate) > 0.01 {
		t.Errorf("hitRate = %f, want ~%f", hitRate, expectedRate)
	}
}

func TestCache_StatsEmpty(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)
	defer cache.Clear()

	hits, misses, hitRate := cache.Stats()
	if hits != 0 || misses != 0 || hitRate != 0 {
		t.Errorf("empty cache stats: hits=%d misses=%d rate=%f", hits, misses, hitRate)
	}
}

func TestCache_Clear(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)

	cache.Set([]byte("a"), &Result{}, 1)
	cache.Set([]byte("b"), &Result{}, 1)
	cache.Get([]byte("a"), 1)

	cache.Clear()

	// Check stats reset BEFORE any new Get (which would increment misses)
	hits, misses, _ := cache.Stats()
	if hits != 0 || misses != 0 {
		t.Errorf("stats should be reset after clear: hits=%d misses=%d", hits, misses)
	}

	// Now verify data is gone
	_, ok := cache.Get([]byte("a"), 1)
	if ok {
		t.Error("expected miss after clear")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE — concurrent access
// ═══════════════════════════════════════════════════════════════════════════════

func TestCache_ConcurrentAccess(t *testing.T) {
	cache := NewResultCache(100, 10*time.Minute)
	defer cache.Clear()

	done := make(chan struct{})

	// Writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				content := []byte{byte(id), byte(j)}
				cache.Set(content, &Result{Confidence: float64(j)}, 1)
			}
		}(i)
	}

	// Readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				content := []byte{byte(id), byte(j)}
				cache.Get(content, 1)
			}
		}(i)
	}

	// Wait for all
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not panic — that's the test
	hits, misses, _ := cache.Stats()
	t.Logf("concurrent: hits=%d misses=%d", hits, misses)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASH CONTENT — покрываем обе ветки (short и large)
// ═══════════════════════════════════════════════════════════════════════════════

func TestHashContent_ShortContent(t *testing.T) {
	data := []byte("short")
	hash := hashContent(data)

	if len(hash) != 64 { // SHA256 hex = 64 chars
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Same content → same hash
	hash2 := hashContent(data)
	if hash != hash2 {
		t.Error("same content should produce same hash")
	}

	// Different content → different hash
	hash3 := hashContent([]byte("other"))
	if hash == hash3 {
		t.Error("different content should produce different hash")
	}
}

func TestHashContent_LargeContent(t *testing.T) {
	// > 64KB to trigger optimized path
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash := hashContent(data)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Deterministic
	hash2 := hashContent(data)
	if hash != hash2 {
		t.Error("same large content should produce same hash")
	}
}

func TestHashContent_MediumContent(t *testing.T) {
	// Between fullHashThreshold and 2*sampleSize boundary
	data := make([]byte, 65*1024) // just above 64KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash := hashContent(data)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestHashContent_VeryLargeContent(t *testing.T) {
	// > 2*sampleSize (64KB) to hit prefix+suffix branch
	data := make([]byte, 100*1024) // 100KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash := hashContent(data)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// hashContent hashes the full content, so a single changed byte anywhere —
	// including the middle of a large blob — must change the hash. A cache
	// keyed on a partial hash would otherwise return another file's result.
	data2 := make([]byte, len(data))
	copy(data2, data)
	data2[len(data)/2] = 0xFF // change middle byte

	hash2 := hashContent(data2)
	if hash == hash2 {
		t.Error("changing a middle byte should change the hash")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE — zero TTL (disabled expiration)
// ═══════════════════════════════════════════════════════════════════════════════

func TestCache_ZeroTTL_NeverExpires(t *testing.T) {
	cache := NewResultCache(100, 0) // TTL disabled
	defer cache.Clear()

	content := []byte("forever")
	cache.Set(content, &Result{Confidence: 0.5}, 1)

	time.Sleep(10 * time.Millisecond)

	_, ok := cache.Get(content, 1)
	if !ok {
		t.Error("with TTL=0, entry should never expire")
	}
}

func TestCache_ReturnsIndependentResultSnapshot(t *testing.T) {
	cache := NewResultCache(2, time.Minute)
	defer cache.Close()
	input := &Result{Findings: []Finding{{Pattern: "original", RiskTags: []string{"crack"}}}}
	cache.Set([]byte("snapshot"), input, 1)

	input.Findings[0].Pattern = "mutated-source"
	input.Findings[0].RiskTags[0] = "mutated-source"
	cached, ok := cache.Get([]byte("snapshot"), 1)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if cached.Findings[0].Pattern != "original" || cached.Findings[0].RiskTags[0] != "crack" {
		t.Fatalf("cache exposed caller mutation: %#v", cached.Findings[0])
	}

	cached.Findings[0].Pattern = "mutated-return"
	again, ok := cache.Get([]byte("snapshot"), 1)
	if !ok || again.Findings[0].Pattern != "original" {
		t.Fatalf("cache exposed returned result mutation: %#v", again)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR — result cache wiring (path/config must be part of the cache key)
// ═══════════════════════════════════════════════════════════════════════════════

func detectorWithPathSite(domain string) *Detector {
	d := &Detector{cache: NewResultCache(10, 0)}
	site := Site{Name: "s", Type: "warez", Domains: []string{domain}, Confidence: 0.9, Scope: []PatternScope{ScopePath}}
	_ = CompileSite(&site)
	d.config.Sites = []Site{site}
	d.rebuildCaches()
	return d
}

func TestDetectorCache_SamePathHitsCache(t *testing.T) {
	d := detectorWithPathSite("warezsite.com")
	content := []byte("plain text body")
	path := "some/warezsite.com/file.smali"

	res1, err := d.Analyze(context.Background(), path, content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res1.Findings) == 0 {
		t.Fatal("expected a path-based finding")
	}

	res2, err := d.Analyze(context.Background(), path, content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res2.Findings) != len(res1.Findings) {
		t.Fatalf("cached result mismatch: %d vs %d findings", len(res1.Findings), len(res2.Findings))
	}
	if hits, _, _ := d.cache.Stats(); hits == 0 {
		t.Error("expected the second Analyze call to hit the cache")
	}
}

func TestDetectorCache_KeyIncludesPath(t *testing.T) {
	d := detectorWithPathSite("warezsite.com")
	content := []byte("identical bytes")

	flagged, err := d.Analyze(context.Background(), "some/warezsite.com/file.smali", content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	clean, err := d.Analyze(context.Background(), "some/other/file.smali", content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(flagged.Findings) == 0 {
		t.Fatal("expected the warez-path file to be flagged")
	}
	if len(clean.Findings) != 0 {
		t.Fatalf("identical content under an unrelated path must not inherit the flagged path's cached result, got %+v", clean.Findings)
	}
}

func TestDetectorCache_InvalidatedByAddSite(t *testing.T) {
	d := NewDetector()
	content := []byte("totallyUniqueSentinelXyz123")
	path := "some/totallyuniquesentinelxyz123.com/file.smali"

	before, err := d.Analyze(context.Background(), path, content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(before.Findings) != 0 {
		t.Fatalf("expected no findings before AddSite, got %+v", before.Findings)
	}

	site := Site{Name: "newsite", Type: "warez", Domains: []string{"totallyuniquesentinelxyz123.com"}, Confidence: 0.9, Scope: []PatternScope{ScopePath}}
	if err := d.AddSite(site); err != nil {
		t.Fatalf("AddSite: %v", err)
	}

	after, err := d.Analyze(context.Background(), path, content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(after.Findings) == 0 {
		t.Fatal("expected AddSite to invalidate the stale cached (clean) result")
	}
}

func TestCache_ConcurrentGetSet(t *testing.T) {
	cache := NewResultCache(16, time.Minute)
	defer cache.Close()
	content := []byte("concurrent")

	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				cache.Set(content, &Result{Confidence: float64(id + n)}, 1)
				_, _ = cache.Get(content, 1)
			}
		}(i)
	}
	workers.Wait()
}
