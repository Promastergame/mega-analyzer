package imageforensics

import (
	"sort"
	"testing"
)

func TestIsAllowedVerdict(t *testing.T) {
	good := []string{
		VerdictOK,
		VerdictSuspicious,
		VerdictPotentiallyUnsafe,
		VerdictUnusualStructure,
		VerdictPossibleEmbedded,
	}
	for _, v := range good {
		if !IsAllowedVerdict(v) {
			t.Errorf("verdict %q should be whitelisted", v)
		}
	}

	bad := []string{
		"virus",
		"malware",
		"",
		"OK",
		"Suspicious",
	}
	for _, v := range bad {
		if IsAllowedVerdict(v) {
			t.Errorf("verdict %q must NOT be whitelisted", v)
		}
	}
}

func TestSanitizeVerdict(t *testing.T) {
	if got := SanitizeVerdict(VerdictOK); got != VerdictOK {
		t.Errorf("ok should pass through, got %q", got)
	}
	// Anything non-whitelisted should fall back to "suspicious".
	if got := SanitizeVerdict("virus"); got != VerdictSuspicious {
		t.Errorf("virus must collapse to suspicious, got %q", got)
	}
	if got := SanitizeVerdict(""); got != VerdictSuspicious {
		t.Errorf("empty must collapse to suspicious, got %q", got)
	}
}

func TestAllowedVerdictsReturnsAll(t *testing.T) {
	got := AllowedVerdicts()
	want := []string{
		VerdictOK,
		VerdictSuspicious,
		VerdictPotentiallyUnsafe,
		VerdictUnusualStructure,
		VerdictPossibleEmbedded,
	}
	if len(got) != len(want) {
		t.Fatalf("AllowedVerdicts returned %d, want %d", len(got), len(want))
	}
	sort.Strings(got)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d]: got %q, want %q", i, got[i], want[i])
		}
	}

	// Mutating the returned slice must not affect future calls.
	got[0] = "tampered"
	again := AllowedVerdicts()
	for _, v := range again {
		if v == "tampered" {
			t.Fatal("AllowedVerdicts must return a fresh slice on every call")
		}
	}
}
