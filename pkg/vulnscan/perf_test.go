package vulnscan

// Tests for the P2-1 performance work: the O(1) ring-buffer Ledger and the
// dynamic-rule regex cache.

import (
	"fmt"
	"testing"
)

func TestLedgerRingBuffer_EvictsOldestAndKeepsOrder(t *testing.T) {
	l := NewLedger(3)
	for i := 1; i <= 5; i++ {
		l.Record(Interaction{CheckID: "C", Body: []byte(fmt.Sprintf("req-%d", i))})
	}
	if l.Count() != 3 {
		t.Fatalf("expected 3 retained entries, got %d", l.Count())
	}
	got := l.FindByCheck("C")
	if len(got) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(got))
	}
	// Oldest two entries (req-1, req-2) must be evicted; remainder in order.
	want := []string{"req-3", "req-4", "req-5"}
	for i, e := range got {
		if string(e.Body) != want[i] {
			t.Errorf("entry %d: got %s, want %s", i, e.Body, want[i])
		}
		if e.ID != uint64(i+3) {
			t.Errorf("entry %d: got ID %d, want %d", i, e.ID, i+3)
		}
	}
}

func TestLedgerRingBuffer_MixedChecksAcrossWrap(t *testing.T) {
	l := NewLedger(4)
	for i := 0; i < 10; i++ {
		check := "A"
		if i%2 == 1 {
			check = "B"
		}
		l.Record(Interaction{CheckID: check, Body: []byte(fmt.Sprintf("%d", i))})
	}
	if l.Count() != 4 {
		t.Fatalf("expected 4 retained entries, got %d", l.Count())
	}
	a := l.FindByCheck("A")
	b := l.FindByCheck("B")
	// Last 4 records are 6(A),7(B),8(A),9(B).
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("expected 2+2 matches, got %d+%d", len(a), len(b))
	}
	if string(a[0].Body) != "6" || string(a[1].Body) != "8" {
		t.Errorf("A entries out of order: %s, %s", a[0].Body, a[1].Body)
	}
	if string(b[0].Body) != "7" || string(b[1].Body) != "9" {
		t.Errorf("B entries out of order: %s, %s", b[0].Body, b[1].Body)
	}
}

func TestCachedRuleRegex_ReusesCompilation(t *testing.T) {
	re1, ok := cachedRuleRegex(`perf-test-\d+`)
	if !ok || re1 == nil {
		t.Fatal("valid pattern must compile")
	}
	re2, ok := cachedRuleRegex(`perf-test-\d+`)
	if !ok || re2 != re1 {
		t.Fatal("cached pattern must return the identical compiled regex")
	}
	if _, ok := cachedRuleRegex(`perf-test-[`); ok {
		t.Fatal("invalid pattern must report failure")
	}
	if _, ok := cachedRuleRegex(`perf-test-[`); ok {
		t.Fatal("invalid pattern must stay rejected (negative cache)")
	}
	if !re1.MatchString("perf-test-42") {
		t.Fatal("compiled regex must still function")
	}
}
