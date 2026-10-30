package ml

import (
	"os"
	"testing"
)

func TestSuggestFeedback(t *testing.T) {
	predictor := NewPatchPredictor(os.Stdout)

	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{
			{FilePath: "Landroidx/core/app/Test1.smali", IsAppCode: false},
			{FilePath: "Landroidx/core/view/Test2.smali", IsAppCode: false},
			{FilePath: "Landroidx/fragment/app/Test3.smali", IsAppCode: false},
			{FilePath: "Landroidx/lifecycle/Test4.smali", IsAppCode: false},
			{FilePath: "Landroidx/activity/Test5.smali", IsAppCode: false},
			{FilePath: "Landroidx/appcompat/Test6.smali", IsAppCode: false}, // 6-й для уверенности
			{FilePath: "myapp/premium/Check.smali", IsAppCode: true},
			{FilePath: "myapp/premium/Verify.smali", IsAppCode: true},
		},
		MediumRisk: []PatchPoint{
			{FilePath: "Lb0/a.smali", IsAppCode: false},
			{FilePath: "Lb0/b.smali", IsAppCode: false},
			{FilePath: "Lb0/c.smali", IsAppCode: false},
		},
		LowRisk: []PatchPoint{},
	}

	suggestions := predictor.SuggestFeedback(prediction)

	// Debug
	t.Logf("Got %d suggestions", len(suggestions))
	for i, s := range suggestions {
		t.Logf("  %d. %s (%s) - %d affected, %.2f confidence",
			i+1, s.Pattern, s.Action, s.AffectedCount, s.Confidence)
	}

	if len(suggestions) == 0 {
		t.Error("Expected suggestions, got none")
		return
	}

	// Должна быть рекомендация для Landroidx
	foundAndroidx := false
	for _, s := range suggestions {
		if s.Pattern == "Landroidx/" && s.Action == "noise" {
			foundAndroidx = true
			if s.AffectedCount < 5 {
				t.Errorf("Landroidx affected count = %d, want >= 5", s.AffectedCount)
			}
			if s.Confidence <= 0 {
				t.Error("Confidence should be positive")
			}
		}
	}

	if !foundAndroidx {
		t.Error("Should suggest Landroidx/ as noise")
	}

	// Должна быть рекомендация для myapp/premium
	foundPremium := false
	for _, s := range suggestions {
		if s.Pattern == "myapp/premium/" && s.Action == "relevant" {
			foundPremium = true
			if s.AffectedCount != 2 {
				t.Errorf("myapp/premium affected count = %d, want 2", s.AffectedCount)
			}
		}
	}

	if !foundPremium {
		t.Error("Should suggest myapp/premium/ as relevant")
	}
}

func TestExtractPackagePrefix(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		levels int
		want   string
	}{
		{
			name:   "simple path",
			path:   "com/example/app/Test.smali",
			levels: 2,
			want:   "com/example/",
		},
		{
			name:   "with smali prefix",
			path:   "smali/com/example/app/Test.smali",
			levels: 2,
			want:   "com/example/",
		},
		{
			name:   "windows path",
			path:   "com\\example\\app\\Test.smali",
			levels: 2,
			want:   "com/example/",
		},
		{
			name:   "single level",
			path:   "com/example/Test.smali",
			levels: 1,
			want:   "com/",
		},
		{
			name:   "more levels than available",
			path:   "com/example/app/Test.smali",
			levels: 5,
			want:   "com/example/app/Test/", // Test - это тоже часть пути
		},
		{
			name:   "empty path",
			path:   "",
			levels: 2,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackagePrefix(tt.path, tt.levels)
			if got != tt.want {
				t.Errorf("extractPackagePrefix(%q, %d) = %q, want %q",
					tt.path, tt.levels, got, tt.want)
			}
		})
	}
}

func TestIsLikelyLibrary(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   bool
	}{
		{"androidx", "androidx/", true},
		{"android", "android/", true},
		{"google", "com/google/", true},
		{"facebook", "com/facebook/", true},
		{"kotlin", "kotlin/", true},
		{"internal", "com/example/internal/", true},
		{"support", "android/support/", true},
		{"app code", "com/myapp/", false},
		{"custom", "myapp/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyLibrary(tt.prefix)
			if got != tt.want {
				t.Errorf("isLikelyLibrary(%q) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestCalculateLibraryConfidence(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		count  int
		total  int
		want   float64
	}{
		{
			name:   "high frequency known library",
			prefix: "androidx/",
			count:  20,
			total:  100,
			want:   0.6, // 0.5*0.2 + 0.3 + 0.1
		},
		{
			name:   "low frequency unknown",
			prefix: "myapp/",
			count:  5,
			total:  100,
			want:   0.025, // 0.5*0.05
		},
		{
			name:   "medium frequency known",
			prefix: "com/google/",
			count:  10,
			total:  100,
			want:   0.45, // 0.5*0.1 + 0.3 + 0.1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateLibraryConfidence(tt.prefix, tt.count, tt.total)
			if got < tt.want-0.01 || got > tt.want+0.01 {
				t.Errorf("calculateLibraryConfidence(%q, %d, %d) = %.3f, want %.3f",
					tt.prefix, tt.count, tt.total, got, tt.want)
			}
		})
	}
}

func TestFindObfuscatedPrefixes(t *testing.T) {
	points := []PatchPoint{
		{FilePath: "La/a.smali"},
		{FilePath: "La/b.smali"},
		{FilePath: "La/c.smali"},
		{FilePath: "Lb/x.smali"},
		{FilePath: "Lb/y.smali"},
		{FilePath: "com/example/Test.smali"},
		{FilePath: "io/test/Test.smali"}, // io - стандартный, не должен попасть
	}

	obfuscated := findObfuscatedPrefixes(points)

	if obfuscated["La/"] != 3 {
		t.Errorf("La/ count = %d, want 3", obfuscated["La/"])
	}

	if obfuscated["Lb/"] != 2 {
		t.Errorf("Lb/ count = %d, want 2", obfuscated["Lb/"])
	}

	if _, exists := obfuscated["io/"]; exists {
		t.Error("io/ should not be detected as obfuscated")
	}

	if _, exists := obfuscated["com/"]; exists {
		t.Error("com/ should not be detected as obfuscated")
	}
}

func TestIsAlphaOnly(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"lowercase", "abc", true},
		{"uppercase", "ABC", true},
		{"mixed", "AbC", true},
		{"with numbers", "abc123", false},
		{"with underscore", "ab_c", false},
		{"with dash", "ab-c", false},
		{"empty", "", false},
		{"single char", "a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAlphaOnly(tt.s)
			if got != tt.want {
				t.Errorf("isAlphaOnly(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestSuggestFeedback_EmptyPrediction(t *testing.T) {
	predictor := NewPatchPredictor(os.Stdout)

	prediction := &PatchPrediction{
		HighRisk:   []PatchPoint{},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
	}

	suggestions := predictor.SuggestFeedback(prediction)

	if len(suggestions) != 0 {
		t.Errorf("Expected no suggestions for empty prediction, got %d", len(suggestions))
	}
}

func TestSuggestFeedback_Sorting(t *testing.T) {
	predictor := NewPatchPredictor(os.Stdout)

	// Создаём prediction с разными паттернами
	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{
			// Много androidx (высокая confidence)
			{FilePath: "Landroidx/a.smali", IsAppCode: false},
			{FilePath: "Landroidx/b.smali", IsAppCode: false},
			{FilePath: "Landroidx/c.smali", IsAppCode: false},
			{FilePath: "Landroidx/d.smali", IsAppCode: false},
			{FilePath: "Landroidx/e.smali", IsAppCode: false},
			{FilePath: "Landroidx/f.smali", IsAppCode: false}, // 6-й для порога
			// Мало custom (низкая confidence)
			{FilePath: "custom/a.smali", IsAppCode: false},
			{FilePath: "custom/b.smali", IsAppCode: false},
			{FilePath: "custom/c.smali", IsAppCode: false},
			{FilePath: "custom/d.smali", IsAppCode: false},
			{FilePath: "custom/e.smali", IsAppCode: false},
		},
	}

	suggestions := predictor.SuggestFeedback(prediction)

	if len(suggestions) < 1 {
		t.Fatal("Expected at least 1 suggestion")
	}

	// Проверяем что есть Landroidx с высокой confidence
	foundHighConfidence := false
	for _, s := range suggestions {
		if s.Pattern == "Landroidx/" && s.Confidence > 0.5 {
			foundHighConfidence = true
			break
		}
	}

	if !foundHighConfidence {
		t.Error("Should have high confidence suggestion for Landroidx/")
	}
}
