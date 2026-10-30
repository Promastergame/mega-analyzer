package matcher

import (
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestMatcher_MatchContent(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher() error = %v", err)
	}

	// Test case: License check (common pattern)
	content := ".method public checkLicense()Z\n" +
		"    const-string v0, \"licensed\"\n" +
		"    invoke-virtual {v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
		"    return v0\n" +
		".end method"

	matches := m.MatchContent(content, "smali/com/app/License.smali")

	// We expect at least some matches if patterns are loaded
	if len(m.GetStats()) == 0 && len(matches) > 0 {
		t.Error("Stats should be updated if matches are found")
	}
}

func TestMatcher_SDKFiltering(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Add a match in an SDK path
	sdkContent := "invoke-virtual {v0}, Lcom/google/android/gms/ads/AdView;->show()V"
	sdkPath := "smali/com/google/android/gms/ads/AdView.smali"

	matches := m.MatchContentWithFilter(sdkContent, sdkPath, true)

	// Should skip Ad matches in SDK path
	for _, match := range matches {
		if sdkNoiseCategories[match.Category] {
			t.Errorf("Should have skipped SDK noise category %v in %s", match.Category, sdkPath)
		}
	}
}

func TestMatcher_Suppression(t *testing.T) {
	// "isprocessed" is a false positive for premium check
	content := "if-eqz v0, :isprocessed"

	if !shouldSuppress(types.CategoryPremiumCheck, "isprocessed", "Any.smali", content) {
		t.Error("shouldSuppress() should return true for 'isprocessed' in PremiumCheck")
	}
}

func TestLineIndex(t *testing.T) {
	content := "line1\nline2\nline3"
	li := buildLineIndex(content)

	if li.lineCount() != 3 {
		t.Errorf("lineCount() = %d, want 3", li.lineCount())
	}
	if li.starts[1] != 6 {
		t.Errorf("starts[1] = %d, want 6", li.starts[1])
	}
}
