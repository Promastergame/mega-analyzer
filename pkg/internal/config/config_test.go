// pkg/internal/config/config_test.go
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ============================================================================
// DefaultConfig
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Workers != runtime.NumCPU() {
		t.Errorf("Workers = %d, want %d", cfg.Workers, runtime.NumCPU())
	}
	if cfg.ContextLines != DefaultContextLines {
		t.Errorf("ContextLines = %d, want %d", cfg.ContextLines, DefaultContextLines)
	}
	if cfg.MaxFileSize != DefaultFileSize {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, DefaultFileSize)
	}
	if cfg.MaxFiles != 0 {
		t.Errorf("MaxFiles = %d, want 0", cfg.MaxFiles)
	}
	if cfg.MinEntropyThreshold != DefaultEntropyThreshold {
		t.Errorf("MinEntropyThreshold = %f, want %f", cfg.MinEntropyThreshold, DefaultEntropyThreshold)
	}
	if cfg.MaxStringLength != DefaultStringLength {
		t.Errorf("MaxStringLength = %d", cfg.MaxStringLength)
	}
	if cfg.MaxMatchesPerFile != DefaultMatchesPerFile {
		t.Errorf("MaxMatchesPerFile = %d", cfg.MaxMatchesPerFile)
	}
	if !cfg.EnableEntropyAnalysis {
		t.Error("EnableEntropyAnalysis should be true")
	}
	if !cfg.EnableCallGraph {
		t.Error("EnableCallGraph should be true")
	}
	if !cfg.EnableCorrelations {
		t.Error("EnableCorrelations should be true")
	}
	if cfg.EnableTracing {
		t.Error("EnableTracing should be false")
	}
	if cfg.OutputFormat != OutputFormatAll {
		t.Errorf("OutputFormat = %q", cfg.OutputFormat)
	}
}

// ============================================================================
// New with Options
// ============================================================================

func TestNew_WithOptions(t *testing.T) {
	cfg := New(
		WithWorkers(8),
		WithContextLines(10),
		WithMaxFileSize(1024*1024),
		WithMaxFiles(123),
		WithEntropyThreshold(5.0),
		WithOutput("out", "json"),
		WithMatchLimits(50, 200),
		WithFeatures(false, true, false, true),
	)

	if cfg.Workers != 8 {
		t.Errorf("Workers = %d", cfg.Workers)
	}
	if cfg.ContextLines != 10 {
		t.Errorf("ContextLines = %d", cfg.ContextLines)
	}
	if cfg.MaxFileSize != 1024*1024 {
		t.Errorf("MaxFileSize = %d", cfg.MaxFileSize)
	}
	if cfg.MaxFiles != 123 {
		t.Errorf("MaxFiles = %d", cfg.MaxFiles)
	}
	if cfg.MinEntropyThreshold != 5.0 {
		t.Errorf("MinEntropyThreshold = %f", cfg.MinEntropyThreshold)
	}
	if cfg.OutputDir != "out" {
		t.Errorf("OutputDir = %q", cfg.OutputDir)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q", cfg.OutputFormat)
	}
	if cfg.MaxMatchesPerFile != 50 {
		t.Errorf("MaxMatchesPerFile = %d", cfg.MaxMatchesPerFile)
	}
	if cfg.MaxMatchesPerCategory != 200 {
		t.Errorf("MaxMatchesPerCategory = %d", cfg.MaxMatchesPerCategory)
	}
	if cfg.EnableEntropyAnalysis {
		t.Error("EnableEntropyAnalysis should be false")
	}
	if cfg.EnableTracing != true {
		t.Error("EnableTracing should be true")
	}
}

func TestNew_WithLogging(t *testing.T) {
	cfg := New(WithLogging(2, "test.log"))

	if cfg.LogLevel != 2 {
		t.Errorf("LogLevel = %d", cfg.LogLevel)
	}
	if cfg.LogFile != "test.log" {
		t.Errorf("LogFile = %q", cfg.LogFile)
	}
}

// ============================================================================
// Validate
// ============================================================================

func TestConfig_Validate_Default(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultConfig().Validate() = %v", err)
	}
}

func TestConfig_Validate_NegativeWorkers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Workers = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative workers")
	}
}

func TestConfig_Validate_ExcessiveWorkers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Workers = MaxWorkers + 1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for excessive workers")
	}
}

func TestConfig_Validate_InvalidContextLines(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ContextLines = MaxContextLines + 1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid context lines")
	}
}

func TestConfig_Validate_InvalidFileSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxFileSize = 100 // too small
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for too small file size")
	}

	cfg.MaxFileSize = MaxFileSize + 1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for too large file size")
	}
}

func TestConfig_Validate_InvalidEntropy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinEntropyThreshold = -1.0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative entropy")
	}

	cfg.MinEntropyThreshold = MaxEntropyThreshold + 1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for excessive entropy")
	}
}

func TestConfig_Validate_InvalidOutputFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputFormat = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid output format")
	}
}

func TestConfig_Validate_EmptyOutputDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputDir = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty output dir")
	}
}

func TestConfig_Validate_InvalidScoreCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ScoreNormalizationCap = 0.0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero score cap")
	}
}

func TestConfig_Validate_MultipleErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Workers = -1
	cfg.OutputDir = ""
	cfg.OutputFormat = "invalid"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}

	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	if len(verrs) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(verrs))
	}
}

// ============================================================================
// Normalize
// ============================================================================

func TestConfig_Normalize(t *testing.T) {
	cfg := &Config{
		Workers:               0,
		ContextLines:          -5,
		MaxFileSize:           100,
		MaxMatchesPerFile:     0,
		MaxMatchesPerCategory: 0,
		OutputFormat:          "INVALID",
		OutputDir:             "",
		ScoreNormalizationCap: 0.0,
		MinEntropyThreshold:   -1.0,
		MaxStringLength:       0,
	}

	cfg.Normalize()

	if cfg.Workers < MinWorkers {
		t.Errorf("Workers = %d, should be >= %d", cfg.Workers, MinWorkers)
	}
	if cfg.ContextLines != MinContextLines {
		t.Errorf("ContextLines = %d, want %d", cfg.ContextLines, MinContextLines)
	}
	if cfg.MaxFileSize != MinFileSize {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, MinFileSize)
	}
	if cfg.MaxMatchesPerFile != DefaultMatchesPerFile {
		t.Errorf("MaxMatchesPerFile = %d", cfg.MaxMatchesPerFile)
	}
	if cfg.OutputFormat != OutputFormatAll {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, OutputFormatAll)
	}
	if cfg.OutputDir != "analysis_output" {
		t.Errorf("OutputDir = %q", cfg.OutputDir)
	}
	if cfg.ScoreNormalizationCap < MinScoreNormalizationCap {
		t.Errorf("ScoreNormalizationCap = %f", cfg.ScoreNormalizationCap)
	}
}

func TestConfig_Normalize_ValidValues(t *testing.T) {
	cfg := DefaultConfig()
	original := cfg.Clone()
	cfg.Normalize()

	// Valid values should not change
	if cfg.Workers != original.Workers {
		t.Errorf("Workers changed from %d to %d", original.Workers, cfg.Workers)
	}
}

// ============================================================================
// Clone
// ============================================================================

func TestConfig_Clone(t *testing.T) {
	cfg := New(WithWorkers(8), WithOutput("test", "json"))
	clone := cfg.Clone()

	if clone.Workers != cfg.Workers {
		t.Error("clone Workers mismatch")
	}
	if clone.OutputDir != cfg.OutputDir {
		t.Error("clone OutputDir mismatch")
	}

	// Modify original, clone should not change
	cfg.Workers = 99
	if clone.Workers == 99 {
		t.Error("clone should be independent")
	}
}

// ============================================================================
// String
// ============================================================================

func TestConfig_String(t *testing.T) {
	cfg := DefaultConfig()
	s := cfg.String()

	if s == "" {
		t.Error("String() returned empty")
	}

	// Should be valid JSON
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Errorf("String() is not valid JSON: %v", err)
	}
}

// ============================================================================
// Getters
// ============================================================================

func TestConfig_Getters(t *testing.T) {
	cfg := New(
		WithWorkers(4),
		WithMaxFileSize(2*1024*1024),
		WithFeatures(true, false, false, false),
	)

	if cfg.GetWorkers() != 4 {
		t.Errorf("GetWorkers() = %d", cfg.GetWorkers())
	}
	if cfg.GetMaxFileSize() != 2*1024*1024 {
		t.Errorf("GetMaxFileSize() = %d", cfg.GetMaxFileSize())
	}
	if !cfg.IsEntropyEnabled() {
		t.Error("IsEntropyEnabled() should be true")
	}
}

// ============================================================================
// Save / Load
// ============================================================================

func TestConfig_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := New(WithWorkers(12), WithOutput("test_out", "html"))
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if loaded.Workers != 12 {
		t.Errorf("loaded Workers = %d", loaded.Workers)
	}
	if loaded.OutputDir != "test_out" {
		t.Errorf("loaded OutputDir = %q", loaded.OutputDir)
	}
	if loaded.OutputFormat != "html" {
		t.Errorf("loaded OutputFormat = %q", loaded.OutputFormat)
	}
}

func TestConfig_LoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestConfig_LoadFromFile_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	os.WriteFile(path, []byte{}, 0644)

	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestConfig_LoadFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConfig_LoadFromFileOrDefault_Missing(t *testing.T) {
	cfg := LoadFromFileOrDefault("/nonexistent.json")
	if cfg == nil {
		t.Fatal("expected default config, got nil")
	}
	if cfg.Workers != runtime.NumCPU() {
		t.Error("expected default config")
	}
}

// ============================================================================
// Error Types
// ============================================================================

func TestValidationError_Error(t *testing.T) {
	e := &ValidationError{
		Field:   "workers",
		Value:   -1,
		Message: "must be positive",
	}
	s := e.Error()
	if s == "" {
		t.Error("Error() returned empty")
	}
}

func TestValidationErrors_Error(t *testing.T) {
	errs := ValidationErrors{
		{Field: "a", Value: 1, Message: "bad"},
		{Field: "b", Value: 2, Message: "worse"},
	}
	s := errs.Error()
	if s == "" {
		t.Error("Error() returned empty")
	}
	if !errs.HasErrors() {
		t.Error("HasErrors() should be true")
	}
}

func TestValidationErrors_Empty(t *testing.T) {
	errs := ValidationErrors{}
	if errs.HasErrors() {
		t.Error("HasErrors() should be false for empty")
	}
	s := errs.Error()
	if s == "" {
		t.Error("Error() should return something even if empty")
	}
}
