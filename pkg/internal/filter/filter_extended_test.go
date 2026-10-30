package filter

import (
	"testing"
)

func TestNewFilter(t *testing.T) {
	filter := NewFilter()

	if filter == nil {
		t.Fatal("NewFilter returned nil")
	}
}

func TestNewFilterWithProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile ProfileType
	}{
		{
			name:    "balanced",
			profile: ProfileBalanced,
		},
		{
			name:    "strict",
			profile: ProfileStrict,
		},
		{
			name:    "loose",
			profile: ProfileLoose,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFilterWithProfile(tt.profile)

			if filter == nil {
				t.Fatal("NewFilterWithProfile returned nil")
			}

			if filter.Profile() != tt.profile {
				t.Errorf("Profile() = %q, want %q", filter.Profile(), tt.profile)
			}
		})
	}
}

func TestFilter_SetAppPackage_Extended(t *testing.T) {
	filter := NewFilter()

	filter.SetAppPackage("com.example.app")

	// Verify package effect via IsAppCode
	if !filter.IsAppCode("smali/com/example/app/MainActivity.smali") {
		t.Error("SetAppPackage should make path app code")
	}
}

func TestClassifyForPipeline_SkipsOnlySafeKnownLibraries(t *testing.T) {
	f := NewFilter()
	if got := f.ClassifyForPipeline("smali/androidx/core/util/Consumer.smali"); !got.SkipFullAnalysis {
		t.Fatal("safe AndroidX class should use the pipeline fast path")
	}
	if got := f.ClassifyForPipeline("smali/com/android/billingclient/api/Purchase.smali"); got.SkipFullAnalysis {
		t.Fatal("billing purchase class must bypass the fast path for full analysis")
	}
}

func TestFilter_Profile_Extended(t *testing.T) {
	filter := NewFilterWithProfile(ProfileBalanced)

	profile := filter.Profile()

	if profile != ProfileBalanced {
		t.Errorf("Profile() = %q, want %q", profile, ProfileBalanced)
	}
}

func TestFilter_IsAppCode_Extended(t *testing.T) {
	filter := NewFilter()
	filter.SetAppPackage("com.example.app")

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "app code",
			path:     "smali/com/example/app/MainActivity.smali",
			expected: true,
		},
		{
			name:     "library code",
			path:     "smali/com/google/android/gms/analytics/Analytics.smali",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.IsAppCode(tt.path)
			if result != tt.expected {
				t.Errorf("IsAppCode(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFilter_GetImportance_Extended(t *testing.T) {
	filter := NewFilter()

	tests := []struct {
		name     string
		path     string
		minScore int
	}{
		{
			name:     "app code",
			path:     "smali/com/example/app/MainActivity.smali",
			minScore: 4,
		},
		{
			name:     "library code",
			path:     "smali/kotlin/Unit.smali",
			minScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := filter.GetImportance(tt.path)
			if score < tt.minScore {
				t.Errorf("GetImportance(%q) = %d, want >= %d", tt.path, score, tt.minScore)
			}
		})
	}
}

func TestFilter_Classify_Extended(t *testing.T) {
	filter := NewFilter()

	tests := []struct {
		name    string
		path    string
		wantNil bool
	}{
		{
			name:    "valid classification",
			path:    "smali/com/example/app/MainActivity.smali",
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.Classify(tt.path)

			if (result == nil) != tt.wantNil {
				t.Errorf("Classify() returned nil = %v, want nil = %v", result == nil, tt.wantNil)
			}
		})
	}
}

func TestFilter_GetCategories_Extended(t *testing.T) {
	filter := NewFilter()

	categories := filter.GetCategories("smali/com/google/android/gms/ads/AdActivity.smali")

	if len(categories) == 0 {
		t.Error("GetCategories should return non-empty list for library path")
	}
}

func TestFilter_Summary_Extended(t *testing.T) {
	filter := NewFilter()

	summary := filter.Summary("smali/com/example/app/MainActivity.smali")

	if summary == "" {
		t.Error("Summary should return non-empty string")
	}
}

func TestFilter_IsHighValue_Extended(t *testing.T) {
	filter := NewFilter()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "high value path",
			path:     "smali/com/example/app/LicenseManager.smali",
			expected: true,
		},
		{
			name:     "low value path",
			path:     "smali/kotlin/Unit.smali",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filter.IsHighValue(tt.path)
			if result != tt.expected {
				t.Errorf("IsHighValue(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkNewFilter_Extended(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewFilter()
	}
}

func BenchmarkFilter_IsAppCode_Extended(b *testing.B) {
	filter := NewFilter()
	filter.SetAppPackage("com.example.app")
	path := "smali/com/example/app/MainActivity.smali"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.IsAppCode(path)
	}
}

func BenchmarkFilter_GetImportance_Extended_Bench(b *testing.B) {
	filter := NewFilter()
	path := "smali/com/example/app/MainActivity.smali"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.GetImportance(path)
	}
}

func BenchmarkFilter_Classify_Extended_Bench(b *testing.B) {
	filter := NewFilter()
	path := "smali/com/example/app/MainActivity.smali"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.Classify(path)
	}
}
