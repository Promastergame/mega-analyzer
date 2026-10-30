package main

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// APPLY PROFILE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestApp_ApplyProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile AnalysisProfile
		checkFn func(*testing.T, *config.Config)
	}{
		{
			name:    "quick profile",
			profile: ProfileQuick,
			checkFn: func(t *testing.T, cfg *config.Config) {
				if cfg.EnableCallGraph {
					t.Error("Quick profile should disable call graph")
				}
				if cfg.EnableCorrelations {
					t.Error("Quick profile should disable correlations")
				}
				if cfg.EnableDataFlow || cfg.EnableDeobfuscation || cfg.EnableCrackPointAnalysis || cfg.EnableAnomalyDetection {
					t.Error("Quick profile should skip expensive second-pass analysis")
				}
			},
		},
		{
			name:    "balanced profile",
			profile: ProfileBalanced,
			checkFn: func(t *testing.T, cfg *config.Config) {
				// Balanced should have some features enabled
				if cfg == nil {
					t.Error("config should not be nil")
				}
			},
		},
		{
			name:    "deep profile",
			profile: ProfileDeep,
			checkFn: func(t *testing.T, cfg *config.Config) {
				if !cfg.EnableCallGraph {
					t.Error("Deep profile should enable call graph")
				}
				if !cfg.EnableCorrelations {
					t.Error("Deep profile should enable correlations")
				}
			},
		},
		{
			name:    "paranoid profile",
			profile: ProfileParanoid,
			checkFn: func(t *testing.T, cfg *config.Config) {
				if !cfg.EnableCallGraph {
					t.Error("Paranoid profile should enable call graph")
				}
				if !cfg.EnableCorrelations {
					t.Error("Paranoid profile should enable correlations")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			app.opts = &CLIOptions{Profile: tt.profile}

			cfg := &config.Config{}
			app.applyProfile(cfg)

			if tt.checkFn != nil {
				tt.checkFn(t, cfg)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACT KEYWORD STATS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestApp_ExtractKeywordStats(t *testing.T) {
	tests := []struct {
		name    string
		result  *types.AnalysisResult
		checkFn func(*testing.T, *types.AnalysisResult)
	}{
		{
			name: "empty result",
			result: &types.AnalysisResult{
				RuleMatches: []types.Match{},
			},
			checkFn: func(t *testing.T, result *types.AnalysisResult) {
				if result == nil {
					t.Error("result should not be nil")
				}
			},
		},
		{
			name: "with matches",
			result: &types.AnalysisResult{
				RuleMatches: []types.Match{
					{
						SourceLocation: types.SourceLocation{File: "test.smali"},
						Categorized:    types.Categorized{Category: types.CategorySecurity},
					},
				},
			},
			checkFn: func(t *testing.T, result *types.AnalysisResult) {
				if len(result.RuleMatches) != 1 {
					t.Errorf("expected 1 match, got %d", len(result.RuleMatches))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			app.opts = &CLIOptions{Profile: ProfileBalanced}

			feedback := &ml.AnalysisFeedback{}
			app.extractKeywordStats(tt.result, feedback)

			if tt.checkFn != nil {
				tt.checkFn(t, tt.result)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACT LIBRARY STATS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestApp_ExtractLibraryStats(t *testing.T) {
	tests := []struct {
		name   string
		result *types.AnalysisResult
	}{
		{
			name: "empty result",
			result: &types.AnalysisResult{
				RuleMatches: []types.Match{},
			},
		},
		{
			name: "with library matches",
			result: &types.AnalysisResult{
				RuleMatches: []types.Match{
					{
						SourceLocation: types.SourceLocation{File: "com/google/android/gms/internal/Class.smali"},
						Categorized:    types.Categorized{Category: types.CategoryAnalytics},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			app.opts = &CLIOptions{Profile: ProfileBalanced}

			feedback := &ml.AnalysisFeedback{}
			app.extractLibraryStats(tt.result, feedback)
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// IS LIBRARY PATH TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsLibraryPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"google play services", "com/google/android/gms/internal/Class.smali", true},
		{"firebase", "com/google/firebase/internal/Class.smali", true},
		{"androidx", "androidx/appcompat/app/AppCompatActivity.smali", true},
		{"support library", "android/support/v7/app/AppCompatActivity.smali", true},
		{"okhttp", "okhttp3/OkHttpClient.smali", true},
		{"retrofit", "retrofit2/Retrofit.smali", true},
		{"app code", "com/example/app/MainActivity.smali", false},
		{"custom package", "com/mycompany/app/Class.smali", false},
		{"empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLibraryPath(tt.path)
			if result != tt.expected {
				t.Errorf("isLibraryPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACT LIBRARY PREFIX TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestExtractLibraryPrefix(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"google play services", "com/google/android/gms/internal/Class.smali", "com/google/android/gms/"},
		{"firebase", "com/google/firebase/internal/Class.smali", "com/google/firebase/"},
		{"androidx", "androidx/appcompat/app/AppCompatActivity.smali", "androidx/"},
		{"okhttp", "okhttp3/OkHttpClient.smali", "okhttp3/"},
		{"retrofit", "retrofit2/Retrofit.smali", "retrofit2/"},
		{"single level", "com/Class.smali", "com/Class/"},
		{"empty path", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLibraryPrefix(tt.path)
			if result != tt.expected {
				t.Errorf("extractLibraryPrefix(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORIZE LIBRARY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCategorizeLibrary(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		expected string
	}{
		{"google play services", "com/google/android/gms/", "google"},
		{"firebase", "com/google/firebase/", "google"},
		{"androidx", "androidx/", "support"},
		{"support library", "android/support/", "support"},
		{"okhttp", "okhttp3/", "network"},
		{"retrofit", "retrofit2/", "network"},
		{"social", "com/facebook/", "social"},
		{"analytics", "com/flurry/", "analytics"},
		{"unknown", "com/unknown/lib/", "other"},
		{"empty", "", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeLibrary(tt.prefix)
			if result != tt.expected {
				t.Errorf("categorizeLibrary(%q) = %q, want %q", tt.prefix, result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCHES PATTERN TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		pattern  string
		expected bool
	}{
		{"exact match", "com/example/Class.smali", "com/example/Class.smali", true},
		{"contains prefix", "com/example/Class.smali", "com/example", true},
		{"contains suffix", "com/example/Class.smali", "Class.smali", true},
		{"contains middle", "com/example/Class.smali", "example", true},
		{"no match", "com/example/Class.smali", "com/other/Class.smali", false},
		{"partial match", "com/example/Class.smali", "com/exam", true},
		{"empty pattern", "com/example/Class.smali", "", true},
		{"empty path", "", "com/example", false},
		{"regex pattern", "com/example/Class.smali", "com/example/.*", true},
		{"case insensitive", "COM/EXAMPLE/CLASS.SMALI", "com/example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPattern(tt.path, tt.pattern)
			if result != tt.expected {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COUNT CRITICAL MATCHES TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCountCriticalMatches(t *testing.T) {
	tests := []struct {
		name     string
		file     *types.FileAnalysis
		expected int
	}{
		{
			name: "no matches",
			file: &types.FileAnalysis{
				Matches: []types.Match{},
			},
			expected: 0,
		},
		{
			name: "all critical",
			file: &types.FileAnalysis{
				Matches: []types.Match{
					{IsCritical: true},
					{IsCritical: true},
					{IsCritical: true},
				},
			},
			expected: 3,
		},
		{
			name: "mixed critical",
			file: &types.FileAnalysis{
				Matches: []types.Match{
					{IsCritical: true},
					{IsCritical: false},
					{IsCritical: true},
				},
			},
			expected: 2,
		},
		{
			name: "no critical",
			file: &types.FileAnalysis{
				Matches: []types.Match{
					{IsCritical: false},
					{IsCritical: false},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countCriticalMatches(tt.file)
			if result != tt.expected {
				t.Errorf("countCriticalMatches() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// WRITE OUTPUT MARKER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestWriteOutputMarker(t *testing.T) {
	tmpDir := t.TempDir()

	err := writeOutputMarker(tmpDir)
	if err != nil {
		t.Fatalf("writeOutputMarker() error = %v", err)
	}

	markerPath := filepath.Join(tmpDir, ".omnisec-output")
	if _, err := os.Stat(markerPath); os.IsNotExist(err) {
		t.Error("marker file was not created")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLEAN OUTPUT DIR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCleanOutputDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create marker file first
	markerPath := filepath.Join(tmpDir, ".omnisec-output")
	if err := os.WriteFile(markerPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create marker file: %v", err)
	}

	// Create some test files
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	err := cleanOutputDir(tmpDir)
	if err != nil {
		t.Fatalf("cleanOutputDir() error = %v", err)
	}
}

func TestCleanOutputDirAdoptsFreshDirs(t *testing.T) {
	// Fresh custom -o dir (missing): adopted, marker stamped, no error.
	missing := filepath.Join(t.TempDir(), "fresh-output")
	if err := cleanOutputDir(missing); err != nil {
		t.Fatalf("cleanOutputDir(missing) error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(missing, ".omnisec-output")); err != nil {
		t.Fatalf("marker not stamped on adopted dir: %v", err)
	}

	// Existing empty dir without marker: adopted as well.
	empty := t.TempDir()
	if err := cleanOutputDir(empty); err != nil {
		t.Fatalf("cleanOutputDir(empty) error = %v", err)
	}

	// Non-empty dir without marker: still refused (may hold foreign data).
	foreign := t.TempDir()
	if err := os.WriteFile(filepath.Join(foreign, "notes.txt"), []byte("mine"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := cleanOutputDir(foreign); err == nil {
		t.Fatal("cleanOutputDir(foreign non-empty dir) succeeded, want refusal")
	}
}

func TestCleanOutputDirAdoptsOwnStartupFiles(t *testing.T) {
	// The logger writes analyzer.log into the output dir at startup, before
	// clean runs. Our own files must not block adoption of a fresh dir.
	ownOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(ownOnly, "analyzer.log"), []byte("log"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ownOnly, ".cache"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := cleanOutputDir(ownOnly); err != nil {
		t.Fatalf("cleanOutputDir(own startup files) error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(ownOnly, ".omnisec-output")); err != nil {
		t.Fatalf("marker not stamped on adopted dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ownOnly, "analyzer.log")); err != nil {
		t.Fatal("owned analyzer.log must survive cleaning")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILTER PATCHES BY CONFIDENCE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestApp_FilterPatchesByConfidence(t *testing.T) {
	tests := []struct {
		name      string
		patches   int
		threshold float64
		expected  int
	}{
		{
			name:      "no patches",
			patches:   0,
			threshold: 0.5,
			expected:  0,
		},
		{
			name:      "all above threshold",
			patches:   5,
			threshold: -0.1, // Ensure all are above
			expected:  5,
		},
		{
			name:      "some above threshold",
			patches:   5,
			threshold: 0.4, // i=3,4 are 0.5, 0.666
			expected:  2,
		},
		{
			name:      "none above threshold",
			patches:   5,
			threshold: 0.99,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()

			// Create test patches with varying confidence
			patches := make([]*ml.GeneratedPatch, tt.patches)
			points := make([]ml.PatchPoint, tt.patches)

			for i := 0; i < tt.patches; i++ {
				confidence := float64(i) / float64(tt.patches+1)
				patches[i] = &ml.GeneratedPatch{
					Confidence: confidence,
				}
				points[i] = ml.PatchPoint{
					Confidence: confidence,
				}
			}

			filtered, _ := app.filterPatchesByConfidence(patches, points, tt.threshold)

			if len(filtered) != tt.expected {
				t.Errorf("%s: got %d patches, want %d", tt.name, len(filtered), tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkIsLibraryPath(b *testing.B) {
	paths := []string{
		"com/google/android/gms/internal/Class.smali",
		"androidx/appcompat/app/AppCompatActivity.smali",
		"com/example/app/MainActivity.smali",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = isLibraryPath(path)
		}
	}
}

func BenchmarkExtractLibraryPrefix(b *testing.B) {
	paths := []string{
		"com/google/android/gms/internal/Class.smali",
		"androidx/appcompat/app/AppCompatActivity.smali",
		"okhttp3/OkHttpClient.smali",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			_ = extractLibraryPrefix(path)
		}
	}
}

func BenchmarkCategorizeLibrary(b *testing.B) {
	prefixes := []string{
		"com/google/android/gms",
		"androidx/appcompat",
		"okhttp3",
		"com/unknown/lib",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, prefix := range prefixes {
			_ = categorizeLibrary(prefix)
		}
	}
}

func BenchmarkMatchesPattern(b *testing.B) {
	tests := []struct {
		path    string
		pattern string
	}{
		{"com/example/Class.smali", "com/example/*"},
		{"com/example/Class.smali", "*/Class.smali"},
		{"com/example/Class.smali", "com/*/Class.smali"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			_ = matchesPattern(tt.path, tt.pattern)
		}
	}
}

func BenchmarkCountCriticalMatches(b *testing.B) {
	file := &types.FileAnalysis{
		Matches: []types.Match{
			{IsCritical: true},
			{IsCritical: false},
			{IsCritical: true},
			{IsCritical: false},
			{IsCritical: true},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = countCriticalMatches(file)
	}
}
