package matcher

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/config"
)

func TestMatchContentParallelLargeContent(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 10k lines with realistic Smali shapes — should fall above the 200KB
	// parallel threshold and exercise the worker dispatch.
	content := generateSmaliContent(10000)
	if len(content) < parallelThreshold {
		t.Skipf("generated content too small for parallel branch (%d bytes)", len(content))
	}

	matches := m.MatchContentParallel(content, strings.ToLower(content), "test.smali", true, 4)
	// Just sanity: should not panic and return a slice.
	if matches == nil {
		// nil is acceptable when no patterns matched
		_ = matches
	}
}

func TestMatchContentParallelSmallContent(t *testing.T) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	// Small content should still work — the function falls back to scanLines
	// internally when only one worker is feasible.
	content := "small content"
	matches := m.MatchContentParallel(content, content, "x.smali", true, 1)
	_ = matches
}

func TestMatchContentParallelEmpty(t *testing.T) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)
	if got := m.MatchContentParallel("", "", "x", true, 4); got != nil {
		t.Errorf("empty content should return nil, got %v", got)
	}
}

func TestMatchContentParallelAutoWorkers(t *testing.T) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(5000)
	// workers=0 → auto, workers=very-large → clamped to maxParallelWorkers.
	for _, w := range []int{0, 100} {
		matches := m.MatchContentParallel(content, strings.ToLower(content), "test.smali", true, w)
		_ = matches
	}
}

func TestMatchContentWithFilterLowerExposesPath(t *testing.T) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(2000)
	lower := strings.ToLower(content)
	matches := m.MatchContentWithFilterLower(content, lower, "test.smali", true)
	_ = matches
}

func TestShouldUseParallelEdgeCases(t *testing.T) {
	if ShouldUseParallel(0, 100) {
		t.Error("zero content should not use parallel")
	}
	if ShouldUseParallel(parallelThreshold-1, 100) {
		t.Error("under-threshold content should not use parallel")
	}
	// >threshold + many candidates → should pick parallel on a multi-CPU host.
	// (We can't force NumCPU, just exercise the call.)
	_ = ShouldUseParallel(parallelThreshold+1, 10)
	if ShouldUseParallel(parallelThreshold+1, 1) {
		t.Error("too few candidates should not use parallel")
	}
}
