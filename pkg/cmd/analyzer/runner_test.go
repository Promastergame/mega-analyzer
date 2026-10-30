package main

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// APP TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewApp(t *testing.T) {
	app := NewApp()
	if app == nil {
		t.Fatal("NewApp() returned nil")
	}
}

func TestAppRun_Commands(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"ml train invalid", []string{"--ml-train", "nonexistent"}, true},
		{"decode invalid", []string{"--decode", "nonexistent.apk"}, true},
		{"js deobf invalid", []string{"--js-deobf", "nonexistent.js"}, true},
		{"js patch invalid", []string{"--js-patch", "nonexistent.js"}, true},
		{"build invalid", []string{"--build", "nonexistent_dir"}, true},
		{"sandbox invalid", []string{"--sandbox", "nonexistent.exe"}, true},
		{"shell invalid", []string{"--shell", "nonexistent.apk"}, true},
		{"web scan invalid", []string{"--web-scan", "--target", ""}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			err := app.Run(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("App.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAppRun_WithEmptyDir(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"decode empty dir", []string{"--decode", "-t", tempDir}, true}, // should fail because it's not an APK
		{"build empty dir", []string{"--build", "-t", tempDir}, true},   // might fail lacking AndroidManifest
		{"js deobf empty dir", []string{"--js-deobf", "-t", tempDir}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			err := app.Run(tt.args)
			if (err != nil) != tt.wantErr {
				t.Logf("App.Run() returned error: %v", err)
				t.Errorf("App.Run() wantErr %v, got error? %v", tt.wantErr, err != nil)
			}
		})
	}
}

func TestApp_ParseFlags(t *testing.T) {
	app := NewApp()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "valid args",
			args:    []string{"-t", "./app"},
			wantErr: false,
		},
		{
			name:    "help flag",
			args:    []string{"--help"},
			wantErr: false,
		},
		{
			name:    "version flag",
			args:    []string{"--version"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := app.parseFlags(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && opts == nil {
				t.Error("parseFlags() returned nil options")
			}
		})
	}
}

func TestApp_HandleSpecialActions(t *testing.T) {
	tests := []struct {
		name        string
		opts        *CLIOptions
		wantHandled bool
	}{
		{
			name:        "version",
			opts:        &CLIOptions{Version: true},
			wantHandled: true,
		},
		{
			name:        "help",
			opts:        &CLIOptions{Help: true},
			wantHandled: true,
		},
		{
			name:        "list profiles",
			opts:        &CLIOptions{ListProfiles: true},
			wantHandled: true,
		},
		{
			name:        "normal analysis",
			opts:        &CLIOptions{Target: "./app"},
			wantHandled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			app.opts = tt.opts

			handled, err := app.handleSpecialActions()
			if err != nil {
				t.Fatalf("handleSpecialActions() error = %v", err)
			}
			if handled != tt.wantHandled {
				t.Errorf("handleSpecialActions() handled = %v, want %v", handled, tt.wantHandled)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD CONFIG TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestApp_BuildConfig(t *testing.T) {
	tests := []struct {
		name    string
		opts    *CLIOptions
		checkFn func(*testing.T, *config.Config)
	}{
		{
			name: "quick profile",
			opts: &CLIOptions{
				Profile: ProfileQuick,
				Workers: 4,
				Output:  "./out",
			},
			checkFn: func(t *testing.T, cfg *config.Config) {
				if cfg.Workers != 4 {
					t.Errorf("Workers = %d, want 4", cfg.Workers)
				}
				if cfg.OutputDir != "./out" {
					t.Errorf("OutputDir = %q, want %q", cfg.OutputDir, "./out")
				}
				if cfg.EnableCallGraph {
					t.Error("Quick profile should disable call graph")
				}
			},
		},
		{
			name: "deep profile",
			opts: &CLIOptions{
				Profile: ProfileDeep,
				Workers: 8,
			},
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
			name: "paranoid profile",
			opts: &CLIOptions{
				Profile: ProfileParanoid,
				Workers: 16,
			},
			checkFn: func(t *testing.T, cfg *config.Config) {
				if !cfg.EnableCallGraph {
					t.Error("Paranoid should enable call graph")
				}
				if !cfg.EnableCorrelations {
					t.Error("Paranoid should enable correlations")
				}
			},
		},
		{
			name: "explicit CLI overrides profile",
			opts: &CLIOptions{
				Profile:              ProfileQuick,
				EnableCallGraph:      true,
				CallGraphExplicit:    true,
				EnableCorrelations:   true,
				CorrelationsExplicit: true,
				Workers:              4,
			},
			checkFn: func(t *testing.T, cfg *config.Config) {
				if !cfg.EnableCallGraph {
					t.Error("Explicit CLI flag should override profile")
				}
				if !cfg.EnableCorrelations {
					t.Error("Explicit CLI flag should override profile")
				}
			},
		},
		{
			name: "max files limit",
			opts: &CLIOptions{
				Profile:  ProfileBalanced,
				Workers:  4,
				MaxFiles: 1000,
			},
			checkFn: func(t *testing.T, cfg *config.Config) {
				if cfg.MaxFiles != 1000 {
					t.Errorf("MaxFiles = %d, want 1000", cfg.MaxFiles)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			app.opts = tt.opts

			cfg := app.buildConfig()
			if cfg == nil {
				t.Fatal("buildConfig() returned nil")
			}

			if tt.checkFn != nil {
				tt.checkFn(t, cfg)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SELECT REPORT OPTIONS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestSelectReportOptions(t *testing.T) {
	tests := []struct {
		name    string
		profile AnalysisProfile
		preset  string
	}{
		{"quick profile auto", ProfileQuick, ""},
		{"balanced profile auto", ProfileBalanced, ""},
		{"deep profile auto", ProfileDeep, ""},
		{"paranoid profile auto", ProfileParanoid, ""},
		{"short preset override", ProfileDeep, "short"},
		{"full preset override", ProfileQuick, "full"},
		{"all preset", ProfileBalanced, "all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := selectReportOptions(tt.profile, tt.preset)
			_ = opts // just check no panic
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML FEEDBACK BUILDER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func createTestMatch(file string, category types.Category, critical bool) types.Match {
	return types.Match{
		SourceLocation: types.SourceLocation{File: file},
		Categorized:    types.Categorized{Category: category},
		IsCritical:     critical,
	}
}

func TestApp_BuildMLFeedback(t *testing.T) {
	app := NewApp()
	app.opts = &CLIOptions{
		Profile: ProfileBalanced,
		Target:  "./test.apk",
	}

	result := &types.AnalysisResult{
		AppPackage: "com.example.app",
		Stats: types.AnalysisStats{
			TotalFiles:    1000,
			AnalyzedFiles: 800,
			TotalMatches:  50,
		},
		RuleMatches: []types.Match{
			createTestMatch("com/example/Class.smali", types.CategorySecurity, true),
			createTestMatch("com/example/Class2.smali", types.CategorySecurity, true),
			createTestMatch("com/example/Class.smali", types.CategoryAnalytics, false),
		},
	}

	feedback := app.buildMLFeedback(result, "./test_app")

	if feedback.Package != "com.example.app" {
		t.Errorf("Package = %q, want %q", feedback.Package, "com.example.app")
	}

	if feedback.TotalFiles != 1000 {
		t.Errorf("TotalFiles = %d, want 1000", feedback.TotalFiles)
	}

	if feedback.CriticalCount != 2 {
		t.Errorf("CriticalCount = %d, want 2", feedback.CriticalCount)
	}

	if len(feedback.CategoryStats) != 2 {
		t.Errorf("CategoryStats length = %d, want 2", len(feedback.CategoryStats))
	}

	if len(feedback.TopFiles) == 0 {
		t.Error("TopFiles should not be empty")
	}
}

func TestCountCritical(t *testing.T) {
	result := &types.AnalysisResult{
		RuleMatches: []types.Match{
			{IsCritical: true},
			{IsCritical: false},
			{IsCritical: true},
			{IsCritical: true},
		},
	}

	count := countCritical(result)
	if count != 3 {
		t.Errorf("countCritical() = %d, want 3", count)
	}
}

func TestBuildTopFiles(t *testing.T) {
	result := &types.AnalysisResult{
		RuleMatches: []types.Match{
			createTestMatch("file1.smali", types.CategorySecurity, false),
			createTestMatch("file1.smali", types.CategorySecurity, false),
			createTestMatch("file1.smali", types.CategoryAnalytics, false),
			createTestMatch("file2.smali", types.CategoryMalwareCombo, false),
			createTestMatch("file3.smali", types.CategorySecurity, false),
		},
	}

	files := buildTopFiles(result)

	if len(files) == 0 {
		t.Fatal("buildTopFiles() returned empty slice")
	}

	// Проверяем сортировку по importance
	if files[0].Path != "file1.smali" {
		t.Errorf("Top file = %q, want %q", files[0].Path, "file1.smali")
	}

	if files[0].Importance != 3 {
		t.Errorf("Top file importance = %d, want 3", files[0].Importance)
	}

	// file1 должен иметь 2 категории
	if len(files[0].Categories) != 2 {
		t.Errorf("Top file categories = %d, want 2", len(files[0].Categories))
	}
}

func TestBuildTopFiles_Limit50(t *testing.T) {
	matches := make([]types.Match, 100)
	for i := range matches {
		matches[i] = createTestMatch("file"+string(rune('A'+i%26))+".smali", types.CategorySecurity, false)
	}

	result := &types.AnalysisResult{
		RuleMatches: matches,
	}

	files := buildTopFiles(result)

	if len(files) > 50 {
		t.Errorf("buildTopFiles() returned %d files, should be capped at 50", len(files))
	}
}

func TestBuildTopFiles_EmptyResult(t *testing.T) {
	result := &types.AnalysisResult{
		RuleMatches: []types.Match{},
	}

	files := buildTopFiles(result)

	if len(files) != 0 {
		t.Errorf("buildTopFiles() should return empty slice for empty input, got %d", len(files))
	}
}

func TestBuildTopFiles_NoFile(t *testing.T) {
	result := &types.AnalysisResult{
		RuleMatches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategorySecurity}}, // no file
		},
	}

	files := buildTopFiles(result)

	if len(files) != 0 {
		t.Errorf("buildTopFiles() should skip matches without file, got %d", len(files))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLEANUP TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestApp_Cleanup(t *testing.T) {
	app := NewApp()

	t.Run("no tempDir", func(t *testing.T) {
		app.tempDir = ""
		app.cleanup() // should not panic
	})

	t.Run("keep-temp flag", func(t *testing.T) {
		app.tempDir = "/tmp/test"
		app.opts = &CLIOptions{KeepTemp: true}
		app.cleanup() // should not delete
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkApp_BuildConfig(b *testing.B) {
	app := NewApp()
	app.opts = &CLIOptions{
		Profile: ProfileDeep,
		Workers: 8,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = app.buildConfig()
	}
}

func BenchmarkBuildMLFeedback(b *testing.B) {
	app := NewApp()
	app.opts = &CLIOptions{Profile: ProfileBalanced}

	matches := make([]types.Match, 100)
	for i := range matches {
		matches[i] = createTestMatch("file.smali", types.CategorySecurity, false)
	}

	result := &types.AnalysisResult{
		AppPackage: "com.test.app",
		Stats: types.AnalysisStats{
			TotalFiles:    1000,
			AnalyzedFiles: 800,
			TotalMatches:  100,
		},
		RuleMatches: matches,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = app.buildMLFeedback(result, "./test")
	}
}

func BenchmarkBuildTopFiles(b *testing.B) {
	matches := make([]types.Match, 1000)
	for i := range matches {
		matches[i] = createTestMatch("file"+string(rune('A'+i%26))+".smali", types.CategorySecurity, false)
	}

	result := &types.AnalysisResult{RuleMatches: matches}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildTopFiles(result)
	}
}
