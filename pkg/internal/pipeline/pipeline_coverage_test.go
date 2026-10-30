package pipeline

import (
	"os"
	"testing"
)

func TestNewUserFeedbackFilter(t *testing.T) {
	f := NewUserFeedbackFilter()
	if f == nil {
		t.Error("NewUserFeedbackFilter returned nil")
	}
}

func TestUserFeedbackFilter_ShouldFilterOut(t *testing.T) {
	f := NewUserFeedbackFilter()

	// Empty filter should not filter anything
	if f.ShouldFilterOut("test/path", []string{"keyword"}) {
		t.Error("Empty filter should not filter out")
	}

	// Add noise pattern (will be normalized internally)
	f.AddNoisePattern("test/path")
	// The path is normalized, so "test/path" matches "test/path" after normalization
	if !f.ShouldFilterOut("test/path", nil) {
		t.Error("Should filter out noise pattern")
	}
}

func TestUserFeedbackFilter_ShouldBoost(t *testing.T) {
	f := NewUserFeedbackFilter()

	// Empty filter should not boost anything
	if f.ShouldBoost("test/path", []string{"keyword"}) {
		t.Error("Empty filter should not boost")
	}

	// Add relevant pattern (will be normalized internally)
	f.AddRelevantPattern("test/path")
	// The path is normalized, so "test/path" matches "test/path" after normalization
	if !f.ShouldBoost("test/path", nil) {
		t.Error("Should boost relevant pattern")
	}
}

func TestUserFeedbackFilter_AddNoiseKeyword(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddNoiseKeyword("testKeyword")

	if !f.ShouldFilterOut("any/path.smali", []string{"testkeyword"}) {
		t.Error("Should filter out by noise keyword (case insensitive)")
	}
}

func TestUserFeedbackFilter_AddRelevantKeyword(t *testing.T) {
	f := NewUserFeedbackFilter()
	f.AddRelevantKeyword("importantKeyword")

	if !f.ShouldBoost("any/path.smali", []string{"importantkeyword"}) {
		t.Error("Should boost by relevant keyword (case insensitive)")
	}
}

func TestUserFeedbackFilter_Stats(t *testing.T) {
	f := NewUserFeedbackFilter()

	f.AddNoisePattern("noise1")
	f.AddRelevantPattern("relevant1")
	f.AddNoiseKeyword("kw1")
	f.AddRelevantKeyword("kw2")

	np, rp, nk, rk := f.Stats()
	if np != 1 || rp != 1 || nk != 1 || rk != 1 {
		t.Errorf("Stats() = (%d, %d, %d, %d), want (1, 1, 1, 1)", np, rp, nk, rk)
	}
}

func TestUserFeedbackFilter_NilReceiver(t *testing.T) {
	var f *UserFeedbackFilter

	// All methods should be safe with nil receiver
	if f.ShouldFilterOut("test", nil) {
		t.Error("nil filter should not filter out")
	}
	if f.ShouldBoost("test", nil) {
		t.Error("nil filter should not boost")
	}

	f.AddNoisePattern("test") // should not panic
	f.AddRelevantPattern("test")
	f.AddNoiseKeyword("test")
	f.AddRelevantKeyword("test")

	np, rp, nk, rk := f.Stats()
	if np != 0 || rp != 0 || nk != 0 || rk != 0 {
		t.Error("nil filter stats should all be 0")
	}
}

func TestUserFeedbackFilter_LoadFromHistory(t *testing.T) {
	f := NewUserFeedbackFilter()

	// Empty path should succeed
	if err := f.LoadFromHistory(""); err != nil {
		t.Errorf("LoadFromHistory('') should succeed, got %v", err)
	}

	// Test with non-existent file (should fail now)
	if err := f.LoadFromHistory("non_existent_file.json"); err == nil {
		t.Error("LoadFromHistory with non-existent path should fail")
	}

	// Test with valid JSON
	tmpFile := "tmp_ml_history.json"
	data := `[{"path": "com/example/test", "label": "noise"}]`
	if err := os.WriteFile(tmpFile, []byte(data), 0644); err != nil {
		t.Fatalf("Failed to create tmp file: %v", err)
	}
	defer os.Remove(tmpFile)

	if err := f.LoadFromHistory(tmpFile); err != nil {
		t.Errorf("LoadFromHistory with valid file failed: %v", err)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"simple path", "com/example/Test", "com/example/test"},
		{"windows path", "com\\example\\Test", "com/example/test"},
		{"smali descriptor", "Lcom/example/Test;", "com/example/test"},
		{"with suffix", "com/example/Test.*", "com/example/test"},
		{"with dot slash", "./com/example/Test", "com/example/test"},
		{"with leading slash", "/com/example/Test", "com/example/test"},
		{"with trailing slash", "com/example/Test/", "com/example/test"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizePath(tc.input)
			if result != tc.expected {
				t.Errorf("normalizePath(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestNormalizeKeyword(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"KEYWORD", "keyword"},
		{"  keyword  ", "keyword"},
		{"KeyWord", "keyword"},
		{"  KEYWORD  ", "keyword"},
	}

	for _, tc := range tests {
		result := normalizeKeyword(tc.input)
		if result != tc.expected {
			t.Errorf("normalizeKeyword(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		pattern  string
		expected bool
	}{
		{"exact match", "com/example/Test", "com/example/test", true},
		{"prefix match", "com/example/Test", "com/example", true},
		{"suffix match", "com/example/Test", "test", true},
		{"contains match", "com/example/Test", "example", true},
		{"wildcard match", "com/example/Test", "com/*", true},
		{"no match", "com/example/Test", "org/test", false},
		{"empty path", "", "pattern", false},
		{"empty pattern", "path", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matchPattern(tc.path, tc.pattern)
			if result != tc.expected {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.path, tc.pattern, result, tc.expected)
			}
		})
	}
}

func TestMatchNormalizedPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		pattern  string
		expected bool
	}{
		{"exact match", "com/example/test", "com/example/test", true},
		{"prefix match", "com/example/test", "com/example", true},
		{"wildcard suffix", "com/example/test", "com/example/*", true},
		{"wildcard prefix", "com/example/test", "*/test", true},
		{"no match", "com/example/test", "org/test", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matchNormalizedPattern(tc.path, tc.pattern)
			if result != tc.expected {
				t.Errorf("matchNormalizedPattern(%q, %q) = %v, want %v", tc.path, tc.pattern, result, tc.expected)
			}
		})
	}
}

func TestFormatLimitMB(t *testing.T) {
	tests := []struct {
		mb       int
		expected string
	}{
		{0, "unlimited"},
		{-1, "unlimited"},
		{16, "16"},
		{32, "32"},
		{100, "100"},
	}

	for _, tc := range tests {
		result := formatLimitMB(tc.mb)
		if result != tc.expected {
			t.Errorf("formatLimitMB(%d) = %q, want %q", tc.mb, result, tc.expected)
		}
	}
}
