package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/piracy"
)

func TestIsBareLuckyPatcherRegex_True(t *testing.T) {
	f := piracy.Finding{Pattern: "lp_crack"}
	if !isBareLuckyPatcherRegex(f) {
		t.Error("expected true for lp_ pattern")
	}
}

func TestIsBareLuckyPatcherRegex_False(t *testing.T) {
	f := piracy.Finding{Pattern: "happymod"}
	if isBareLuckyPatcherRegex(f) {
		t.Error("expected false for non-lp_ pattern")
	}
}

func TestFileHasStrongLuckyPatcher_Found(t *testing.T) {
	findings := []piracy.Finding{
		{Pattern: "luckypatcher_install"},
	}
	if !fileHasStrongLuckyPatcher(findings) {
		t.Error("expected true for luckypatcher pattern")
	}
}

func TestFileHasStrongLuckyPatcher_Chelpus(t *testing.T) {
	findings := []piracy.Finding{
		{Pattern: "chelpus_key"},
	}
	if !fileHasStrongLuckyPatcher(findings) {
		t.Error("expected true for chelpus pattern")
	}
}

func TestFileHasStrongLuckyPatcher_NotFound(t *testing.T) {
	findings := []piracy.Finding{
		{Pattern: "happymod"},
	}
	if fileHasStrongLuckyPatcher(findings) {
		t.Error("expected false for non-lp pattern")
	}
}

func TestFileHasStrongLuckyPatcher_Empty(t *testing.T) {
	if fileHasStrongLuckyPatcher(nil) {
		t.Error("expected false for nil")
	}
}

func TestIsWeakModToken_NoAds(t *testing.T) {
	f := piracy.Finding{Type: "mod", Pattern: "no_ads"}
	if !isWeakModToken(f) {
		t.Error("no_ads should be weak mod token")
	}
}

func TestIsWeakModToken_AdFree(t *testing.T) {
	f := piracy.Finding{Type: "mod", Pattern: "ad_free"}
	if !isWeakModToken(f) {
		t.Error("ad_free should be weak mod token")
	}
}

func TestIsWeakModToken_NotMod(t *testing.T) {
	f := piracy.Finding{Type: "crack", Pattern: "no_ads"}
	if isWeakModToken(f) {
		t.Error("non-mod type should not be weak mod token")
	}
}

func TestIsWeakModToken_StrongMod(t *testing.T) {
	f := piracy.Finding{Type: "mod", Pattern: "unlimited_coins"}
	if isWeakModToken(f) {
		t.Error("unlimited_coins should not be weak mod token")
	}
}

func TestFileHasIndependentPiracySignal_Crack(t *testing.T) {
	findings := []piracy.Finding{
		{Type: "crack", Pattern: "crack_license"},
	}
	if !fileHasIndependentPiracySignal(findings) {
		t.Error("crack type should be independent signal")
	}
}

func TestFileHasIndependentPiracySignal_Site(t *testing.T) {
	findings := []piracy.Finding{
		{Type: "site", Pattern: "apkpure"},
	}
	if !fileHasIndependentPiracySignal(findings) {
		t.Error("site type should be independent signal")
	}
}

func TestFileHasIndependentPiracySignal_WeakModOnly(t *testing.T) {
	findings := []piracy.Finding{
		{Type: "mod", Pattern: "no_ads"},
	}
	if fileHasIndependentPiracySignal(findings) {
		t.Error("weak mod only should NOT be independent signal")
	}
}

func TestFileHasIndependentPiracySignal_StrongMod(t *testing.T) {
	findings := []piracy.Finding{
		{Type: "mod", Pattern: "unlimited_everything"},
	}
	if !fileHasIndependentPiracySignal(findings) {
		t.Error("strong mod should be independent signal")
	}
}

func TestFileHasIndependentPiracySignal_Empty(t *testing.T) {
	if fileHasIndependentPiracySignal(nil) {
		t.Error("nil should not be independent signal")
	}
}
