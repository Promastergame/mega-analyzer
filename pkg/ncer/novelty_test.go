package ncer

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

func testTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ncer-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var lastErr error
		for attempt := 0; attempt < 5; attempt++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			} else {
				lastErr = err
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("cleanup temp dir: %v", lastErr)
	})
	return dir
}

func TestCollector_ScoreNovelty_NoBaselineDirLeavesZero(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")
	result := &types.NcerCausalResult{}
	c.scoreNovelty(result)
	if result.DNovelty != 0.0 {
		t.Errorf("DNovelty with no baseline dir = %v, want 0.0", result.DNovelty)
	}
}

func TestCollector_ScoreNovelty_FirstSessionIsFullyNovel(t *testing.T) {
	c := NewCollector(time.Now())
	c.SetBaselineDir(testTempDir(t))
	c.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")
	c.ObserveHTTP("GET", "https://example.test/b", "200", "example.test", "")

	result := &types.NcerCausalResult{}
	c.scoreNovelty(result)
	if result.DNovelty != 1.0 {
		t.Errorf("first-ever session DNovelty = %v, want 1.0 (nothing in baseline yet)", result.DNovelty)
	}
}

func TestCollector_ScoreNovelty_RepeatedSessionIsNotNovel(t *testing.T) {
	dir := testTempDir(t)

	first := NewCollector(time.Now())
	first.SetBaselineDir(dir)
	first.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")
	first.scoreNovelty(&types.NcerCausalResult{})

	second := NewCollector(time.Now())
	second.SetBaselineDir(dir)
	second.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")

	result := &types.NcerCausalResult{}
	second.scoreNovelty(result)
	if result.DNovelty != 0.0 {
		t.Errorf("repeating an already-baselined fingerprint should score 0.0 novelty, got %v", result.DNovelty)
	}
}

func TestCollector_ScoreNovelty_PartialOverlapIsFractional(t *testing.T) {
	dir := testTempDir(t)

	first := NewCollector(time.Now())
	first.SetBaselineDir(dir)
	first.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")
	first.scoreNovelty(&types.NcerCausalResult{})

	second := NewCollector(time.Now())
	second.SetBaselineDir(dir)
	second.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "") // known
	second.ObserveHTTP("GET", "https://example.test/b", "200", "example.test", "") // novel

	result := &types.NcerCausalResult{}
	second.scoreNovelty(result)
	if abs32(result.DNovelty-0.5) > 1e-6 {
		t.Errorf("one known + one novel fingerprint should score 0.5, got %v", result.DNovelty)
	}
}

func TestCollector_ScoreNovelty_NoEventsLeavesZero(t *testing.T) {
	c := NewCollector(time.Now())
	c.SetBaselineDir(testTempDir(t))
	result := &types.NcerCausalResult{}
	c.scoreNovelty(result)
	if result.DNovelty != 0.0 {
		t.Errorf("DNovelty with no observed events = %v, want 0.0", result.DNovelty)
	}
}

// TestCollector_ScoreNovelty_ConcurrentNoLostUpdate runs many sessions that
// each learn a distinct fingerprint against one shared baseline directory,
// concurrently. The file lock must serialise their read-modify-write so every
// fingerprint survives — a lost update would leave the final baseline missing
// some, which a fresh read-only pass would then wrongly score as novel.
func TestCollector_ScoreNovelty_ConcurrentNoLostUpdate(t *testing.T) {
	dir := testTempDir(t)
	const n = 24

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := NewCollector(time.Now())
			c.SetBaselineDir(dir)
			c.ObserveHTTP("GET", fmt.Sprintf("https://example.test/%d", i), "200", "example.test", "")
			c.scoreNovelty(&types.NcerCausalResult{})
		}()
	}
	wg.Wait()

	// Every fingerprint must now be in the baseline: a final session repeating
	// all of them read-only should see zero novelty.
	verifier := NewCollector(time.Now())
	for i := 0; i < n; i++ {
		verifier.ObserveHTTP("GET", fmt.Sprintf("https://example.test/%d", i), "200", "example.test", "")
	}
	if got := verifier.ScoreNoveltyReadOnly(dir); got != 0.0 {
		t.Errorf("after %d concurrent learning sessions, read-only novelty = %v, want 0.0 (lost update)", n, got)
	}
}

// TestCollector_ScoreNoveltyReadOnly_DoesNotMutate verifies the read-only
// scorer never folds the session into the baseline, so repeated calls are
// reproducible.
func TestCollector_ScoreNoveltyReadOnly_DoesNotMutate(t *testing.T) {
	dir := testTempDir(t)
	c := NewCollector(time.Now())
	c.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")

	first := c.ScoreNoveltyReadOnly(dir)
	second := c.ScoreNoveltyReadOnly(dir)
	if first != 1.0 || second != 1.0 {
		t.Errorf("read-only novelty should stay 1.0 across calls (no learning), got %v then %v", first, second)
	}
}

func TestCollector_ScoreNovelty_TLSAndFlowContribute(t *testing.T) {
	dir := testTempDir(t)

	// First session learns an HTTP request, a TLS handshake and a flow.
	first := NewCollector(time.Now())
	first.SetBaselineDir(dir)
	first.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "")
	first.ObserveTLS("example.test", "TLS_AES_128_GCM", "771,4865-4866", "ja3hashAAA", nil, []string{"h2"}, "")
	first.ObserveFlow("10.0.0.1", 44000, "93.184.216.34", 443, 1200, 50, "tcp", "")
	first.scoreNovelty(&types.NcerCausalResult{})

	// Second session repeats the HTTP request (known) but presents a NEW JA3
	// and a NEW flow destination — both must register as novel.
	second := NewCollector(time.Now())
	second.SetBaselineDir(dir)
	second.ObserveHTTP("GET", "https://example.test/a", "200", "example.test", "") // known
	second.ObserveTLS("example.test", "TLS_AES_128_GCM", "771,9999", "ja3hashZZZ", nil, nil, "")
	second.ObserveFlow("10.0.0.1", 44001, "1.2.3.4", 8443, 900, 30, "tcp", "")

	result := &types.NcerCausalResult{}
	second.scoreNovelty(result)
	// 3 fingerprints total (http, tls, flow); 1 known (http) + 2 novel.
	if abs32(result.DNovelty-2.0/3.0) > 1e-6 {
		t.Errorf("DNovelty with a new JA3 and flow = %v, want ~0.667", result.DNovelty)
	}
}

func TestCollector_ScoreNovelty_SameJA3IsNotNovel(t *testing.T) {
	dir := testTempDir(t)

	first := NewCollector(time.Now())
	first.SetBaselineDir(dir)
	first.ObserveTLS("a.test", "TLS_AES_128_GCM", "771,4865", "ja3same", nil, nil, "")
	first.scoreNovelty(&types.NcerCausalResult{})

	// Same JA3 hash, different SNI — JA3 is the canonical key, so this is NOT
	// novel (the client stack is unchanged).
	second := NewCollector(time.Now())
	second.SetBaselineDir(dir)
	second.ObserveTLS("b.test", "TLS_AES_128_GCM", "771,4865", "ja3same", nil, nil, "")

	result := &types.NcerCausalResult{}
	second.scoreNovelty(result)
	if result.DNovelty != 0.0 {
		t.Errorf("same JA3 hash should score 0.0 novelty, got %v", result.DNovelty)
	}
}
