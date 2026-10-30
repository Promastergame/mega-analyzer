package matcher

import (
	"runtime"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Tests for helper functions to increase coverage
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsSDKPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"androidx library", "smali/androidx/core/app/Activity.smali", true},
		{"google gms", "smali/com/google/android/gms/ads/AdView.smali", true},
		{"unity ads", "smali/com/unity3d/ads/UnityAds.smali", true},
		{"applovin", "smali/com/applovin/sdk/AppLovinSdk.smali", true},
		{"okhttp", "smali/okhttp3/OkHttpClient.smali", true},
		{"kotlin", "smali/kotlin/collections/List.smali", true},
		{"app code", "smali/com/myapp/MainActivity.smali", false},
		{"custom package", "smali/com/example/app/Utils.smali", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSDKPath(tt.path)
			if result != tt.expected {
				t.Errorf("isSDKPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsPremiumFalsePositive(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected bool
	}{
		{"isprocessed FP", "isprocessed", true},
		{"isproxyclass FP", "isproxyclass", true},
		{"isproduction FP", "isproduction", true},
		{"premium in app", "com.myapp.premium.Manager", false},
		{"premium standalone", "isPremium", false},
		{"premium check", "checkPremium", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPremiumFalsePositive(tt.text)
			if result != tt.expected {
				t.Errorf("isPremiumFalsePositive(%q) = %v, want %v", tt.text, result, tt.expected)
			}
		})
	}
}

func TestIsASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"pure ASCII", "hello world", true},
		{"ASCII with numbers", "test123", true},
		{"ASCII with symbols", "test_123-abc", true},
		{"unicode", "привет", false},
		{"mixed", "hello мир", false},
		{"emoji", "test 😀", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isASCII(tt.input)
			if result != tt.expected {
				t.Errorf("isASCII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a        int
		b        int
		expected int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{5, 5, 5},
		{-5, 10, -5},
		{10, -5, -5},
		{0, 0, 0},
	}

	for _, tt := range tests {
		result := minInt(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestShouldUseParallel(t *testing.T) {
	// Skip if single CPU
	if runtime.NumCPU() < 2 {
		t.Skip("Skipping on single CPU system")
	}

	tests := []struct {
		name           string
		contentLen     int
		candidateCount int
		expected       bool
	}{
		{"small content, few candidates", 1000, 10, false},
		{"large content, few candidates", 300000, 10, true},   // 300KB >= 200KB threshold
		{"small content, many candidates", 1000, 100, false},  // 1KB < 200KB threshold
		{"large content, many candidates", 300000, 100, true}, // 300KB >= 200KB threshold
		{"threshold content", 204800, 50, true},               // Exactly at threshold
		{"below threshold", 10000, 10, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldUseParallel(tt.contentLen, tt.candidateCount)
			if result != tt.expected {
				t.Errorf("ShouldUseParallel(%d, %d) = %v, want %v",
					tt.contentLen, tt.candidateCount, result, tt.expected)
			}
		})
	}
}

func TestGetAllPatterns(t *testing.T) {
	patterns := GetAllPatterns()

	if len(patterns) == 0 {
		t.Error("GetAllPatterns() should return at least one pattern")
	}

	// Check that all patterns have required fields
	for i, p := range patterns {
		if p.Category == "" {
			t.Errorf("Pattern %d has empty category", i)
		}
		if p.Pattern == "" {
			t.Errorf("Pattern %d (%v) has no pattern", i, p.Category)
		}
	}
}

func TestCompile(t *testing.T) {
	compiled, err := Compile()
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	if compiled == nil {
		t.Fatal("Compile() returned nil")
	}
}

func TestGetLicensePatterns(t *testing.T) {
	patterns := getLicensePatterns()

	if len(patterns) == 0 {
		t.Error("getLicensePatterns() should return at least one pattern")
	}
}

func TestGetBillingPatterns(t *testing.T) {
	patterns := getBillingPatterns()

	if len(patterns) == 0 {
		t.Error("getBillingPatterns() should return at least one pattern")
	}
}

func TestGetPremiumPatterns(t *testing.T) {
	patterns := getPremiumPatterns()

	if len(patterns) == 0 {
		t.Error("getPremiumPatterns() should return at least one pattern")
	}
}

func TestAhoCorasick_GetPutScratch(t *testing.T) {
	ac := NewAhoCorasick([]string{"test", "pattern"})

	// Get scratch
	scratch1 := ac.getScratch()
	if scratch1 == nil {
		t.Fatal("getScratch() returned nil")
	}

	// Put it back
	ac.putScratch(scratch1)

	// Get again - should reuse
	scratch2 := ac.getScratch()
	if scratch2 == nil {
		t.Fatal("getScratch() returned nil on second call")
	}

	// Put it back
	ac.putScratch(scratch2)
}

func TestAhoScratch_AdvanceGen(t *testing.T) {
	scratch := &ahoScratch{
		gen: 1,
	}

	scratch.advanceGen()

	if scratch.gen != 2 {
		t.Errorf("advanceGen() gen = %d, want 2", scratch.gen)
	}

	// Test overflow - uint32 max is 0xFFFFFFFF
	scratch.gen = 0xFFFFFFFF
	scratch.advanceGen()

	// After overflow, gen should be reset to 1 (after incrementing to 0, then reset)
	if scratch.gen != 1 {
		t.Errorf("advanceGen() overflow gen = %d, want 1", scratch.gen)
	}
}

func TestNewACNode(t *testing.T) {
	node := newACNode()

	// Just verify it doesn't crash
	if node.fail < 0 {
		t.Error("newACNode() should initialize properly")
	}
}
