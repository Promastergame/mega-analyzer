package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfigFile_NonExistent(t *testing.T) {
	result, err := ValidateConfigFile("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatal("should be invalid for nonexistent file")
	}
	if len(result.Errors) == 0 {
		t.Fatal("should have errors")
	}
}

func TestValidateConfigFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid json"), 0644)

	result, err := ValidateConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatal("should be invalid for bad JSON")
	}
	if len(result.Errors) == 0 {
		t.Fatal("should have JSON parse error")
	}
}

func TestValidateConfigFile_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Config{
		Workers:   4,
		OutputDir: "output",
	}
	data, _ := json.Marshal(&cfg)
	os.WriteFile(path, data, 0644)

	result, err := ValidateConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("should be valid, errors: %v", result.Errors)
	}
}

func TestValidateConfigFile_HighWorkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Config{Workers: 200, OutputDir: "out"}
	data, _ := json.Marshal(&cfg)
	os.WriteFile(path, data, 0644)

	result, _ := ValidateConfigFile(path)
	found := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected warning for high worker count")
	}
}

func TestValidateWorkers(t *testing.T) {
	tests := []struct {
		workers  int
		wantWarn bool
	}{
		{0, true},
		{-1, true},
		{4, false},
		{128, false},
		{200, true},
	}
	for _, tt := range tests {
		warnings := validateWorkers(tt.workers)
		if tt.wantWarn && len(warnings) == 0 {
			t.Errorf("workers=%d: expected warning", tt.workers)
		}
		if !tt.wantWarn && len(warnings) > 0 {
			t.Errorf("workers=%d: unexpected warning: %v", tt.workers, warnings)
		}
	}
}

func TestValidateFileSizes(t *testing.T) {
	// Both set
	warnings := validateFileSizes(1024, 10, 0)
	if len(warnings) == 0 {
		t.Fatal("expected warning when both max_file_size and max_file_size_mb are set")
	}

	// Very large MB
	warnings = validateFileSizes(0, 2000, 0)
	if len(warnings) == 0 {
		t.Fatal("expected warning for very large max_file_size_mb")
	}

	// Very large resource
	warnings = validateFileSizes(0, 0, 2000)
	if len(warnings) == 0 {
		t.Fatal("expected warning for very large max_resource_size_mb")
	}

	// Normal values
	warnings = validateFileSizes(0, 100, 100)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestValidateOutputDir(t *testing.T) {
	// Empty
	warnings := validateOutputDir("")
	if len(warnings) == 0 {
		t.Fatal("expected warning for empty output_dir")
	}

	// Valid
	warnings = validateOutputDir("analysis_output")
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestValidateLogging(t *testing.T) {
	// Valid levels
	for _, level := range []string{"debug", "info", "warn", "error"} {
		warnings := validateLogging(level, "")
		if len(warnings) != 0 {
			t.Errorf("level=%q: unexpected warnings: %v", level, warnings)
		}
	}

	// Invalid level
	warnings := validateLogging("verbose", "")
	if len(warnings) == 0 {
		t.Fatal("expected warning for invalid log level")
	}

	// Log file without .log extension
	warnings = validateLogging("info", "output.txt")
	if len(warnings) == 0 {
		t.Fatal("expected warning for log file without .log extension")
	}

	// Valid log file
	warnings = validateLogging("info", "app.log")
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestSuggestOptimizations(t *testing.T) {
	cfg := &Config{
		Workers:            0,
		MaxFileSizeMB:      0,
		MaxResourceSizeMB:  0,
		EnableCorrelations: true,
		EnableCallGraph:    false,
	}
	suggestions := suggestOptimizations(cfg)
	if len(suggestions) == 0 {
		t.Fatal("expected suggestions for default config")
	}
}

func TestValidationResult_Print(t *testing.T) {
	r := &ValidationResult{
		Valid:       true,
		Path:        "test.json",
		Warnings:    []string{"warning1"},
		Errors:      nil,
		Suggestions: []string{"suggestion1"},
	}
	// Should not panic
	r.Print()
}

func TestValidationResult_PrintJSON(t *testing.T) {
	r := &ValidationResult{
		Valid:       true,
		Path:        "test.json",
		Warnings:    []string{},
		Errors:      []string{},
		Suggestions: []string{},
	}
	err := r.PrintJSON()
	if err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Env config tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestLoadEnvConfig_Empty(t *testing.T) {
	// Clear all env vars
	for _, key := range []string{
		EnvConfigPath, EnvCacheDir, EnvOutputDir, EnvWorkers,
		EnvTimeout, EnvMaxFiles, EnvMaxFileSizeMB, EnvMaxResourceSizeMB,
		EnvLogLevel, EnvLogFile, EnvProfile, EnvDebug, EnvQuiet, EnvNoColor,
	} {
		os.Unsetenv(key)
	}

	cfg := LoadEnvConfig()
	if cfg != nil {
		t.Fatal("expected nil when no env vars set")
	}
}

func TestLoadEnvConfig_WithValues(t *testing.T) {
	t.Setenv(EnvWorkers, "8")
	t.Setenv(EnvOutputDir, "/tmp/output")
	t.Setenv(EnvDebug, "true")
	t.Setenv(EnvLogLevel, "DEBUG")
	t.Setenv(EnvProfile, "DEEP")

	cfg := LoadEnvConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Workers != 8 {
		t.Fatalf("Workers = %d, want 8", cfg.Workers)
	}
	if cfg.OutputDir != "/tmp/output" {
		t.Fatalf("OutputDir = %q", cfg.OutputDir)
	}
	if !cfg.Debug {
		t.Fatal("Debug should be true")
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want 'debug'", cfg.LogLevel)
	}
	if cfg.Profile != "deep" {
		t.Fatalf("Profile = %q, want 'deep'", cfg.Profile)
	}
}

func TestLoadEnvConfig_InvalidWorkers(t *testing.T) {
	t.Setenv(EnvWorkers, "invalid")
	t.Setenv(EnvOutputDir, "out") // need at least one valid field

	cfg := LoadEnvConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Workers != 0 {
		t.Fatalf("Workers should be 0 for invalid value, got %d", cfg.Workers)
	}
}

func TestIsTruthy(t *testing.T) {
	truthy := []string{"1", "true", "yes", "on", "TRUE", "Yes", "ON", " true "}
	for _, v := range truthy {
		if !isTruthy(v) {
			t.Errorf("isTruthy(%q) should be true", v)
		}
	}

	falsy := []string{"0", "false", "no", "off", "", "maybe"}
	for _, v := range falsy {
		if isTruthy(v) {
			t.Errorf("isTruthy(%q) should be false", v)
		}
	}
}

func TestEnvConfig_IsEmpty(t *testing.T) {
	cfg := &EnvConfig{}
	if !cfg.IsEmpty() {
		t.Fatal("default EnvConfig should be empty")
	}

	cfg.Workers = 4
	if cfg.IsEmpty() {
		t.Fatal("should not be empty with Workers set")
	}
}

func TestGetEnvHelp(t *testing.T) {
	help := GetEnvHelp()
	if help == "" {
		t.Fatal("help should not be empty")
	}
	if !containsStr(help, EnvWorkers) {
		t.Fatal("help should mention ANALYZER_WORKERS")
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════
// Additional config tests for coverage boost
// ═══════════════════════════════════════════════════════════════════

func TestLoadEnvConfig_AllFields(t *testing.T) {
	t.Setenv(EnvConfigPath, "/path/to/config.json")
	t.Setenv(EnvCacheDir, "/cache")
	t.Setenv(EnvOutputDir, "/output")
	t.Setenv(EnvWorkers, "16")
	t.Setenv(EnvTimeout, "300")
	t.Setenv(EnvMaxFiles, "1000")
	t.Setenv(EnvMaxFileSizeMB, "50")
	t.Setenv(EnvMaxResourceSizeMB, "100")
	t.Setenv(EnvLogLevel, "warn")
	t.Setenv(EnvLogFile, "/tmp/app.log")
	t.Setenv(EnvProfile, "balanced")
	t.Setenv(EnvDebug, "1")
	t.Setenv(EnvQuiet, "yes")
	t.Setenv(EnvNoColor, "on")

	cfg := LoadEnvConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.ConfigPath != "/path/to/config.json" {
		t.Fatalf("ConfigPath = %q", cfg.ConfigPath)
	}
	if cfg.CacheDir != "/cache" {
		t.Fatalf("CacheDir = %q", cfg.CacheDir)
	}
	if cfg.Workers != 16 {
		t.Fatalf("Workers = %d", cfg.Workers)
	}
	if cfg.Timeout != 300 {
		t.Fatalf("Timeout = %d", cfg.Timeout)
	}
	if cfg.MaxFiles != 1000 {
		t.Fatalf("MaxFiles = %d", cfg.MaxFiles)
	}
	if cfg.MaxFileSizeMB != 50 {
		t.Fatalf("MaxFileSizeMB = %d", cfg.MaxFileSizeMB)
	}
	if cfg.MaxResourceSizeMB != 100 {
		t.Fatalf("MaxResourceSizeMB = %d", cfg.MaxResourceSizeMB)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.LogFile != "/tmp/app.log" {
		t.Fatalf("LogFile = %q", cfg.LogFile)
	}
	if cfg.Profile != "balanced" {
		t.Fatalf("Profile = %q", cfg.Profile)
	}
	if !cfg.Debug {
		t.Fatal("Debug should be true")
	}
	if !cfg.Quiet {
		t.Fatal("Quiet should be true")
	}
	if !cfg.NoColor {
		t.Fatal("NoColor should be true")
	}
}

func TestLoadEnvConfig_NegativeWorkers(t *testing.T) {
	t.Setenv(EnvWorkers, "-5")
	t.Setenv(EnvOutputDir, "out")

	cfg := LoadEnvConfig()
	if cfg == nil {
		t.Fatal("expected non-nil")
	}
	if cfg.Workers != 0 {
		t.Fatalf("negative workers should be ignored, got %d", cfg.Workers)
	}
}

func TestLoadEnvConfig_ZeroTimeout(t *testing.T) {
	t.Setenv(EnvTimeout, "0")
	t.Setenv(EnvOutputDir, "out")

	cfg := LoadEnvConfig()
	if cfg == nil {
		t.Fatal("expected non-nil")
	}
	if cfg.Timeout != 0 {
		t.Fatalf("Timeout = %d, want 0", cfg.Timeout)
	}
}

func TestValidateConfigFile_LargeResourceSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := Config{
		Workers:           4,
		OutputDir:         "out",
		MaxFileSizeMB:     2000,
		MaxResourceSizeMB: 2000,
	}
	data, _ := json.Marshal(&cfg)
	os.WriteFile(path, data, 0644)

	result, _ := ValidateConfigFile(path)
	// Should have warnings about large sizes
	hasWarning := false
	for _, w := range result.Warnings {
		if len(w) > 0 {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Fatal("expected warnings for large file sizes")
	}
}

func TestValidateConfigFile_EmptyJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte("{}"), 0644)

	result, err := ValidateConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatal("empty JSON should be valid")
	}
}

func TestSuggestOptimizations_DebugMode(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}
	suggestions := suggestOptimizations(cfg)
	if len(suggestions) == 0 {
		t.Fatal("expected at least one suggestion")
	}
}

func TestValidateOutputDir_InvalidChars(t *testing.T) {
	warnings := validateOutputDir("out*put")
	if len(warnings) == 0 {
		t.Fatal("expected warning for invalid chars in output dir")
	}
}
