package apkloader

import (
	"context"
	"mega-analyzer/pkg/internal/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTOR EXTENDED TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewExtractor_Defaults(t *testing.T) {
	e := NewExtractor()

	if e == nil {
		t.Fatal("NewExtractor() returned nil")
	}

	if e.TempDir == "" {
		t.Error("TempDir should not be empty")
	}

	if e.Warnings == nil {
		t.Error("Warnings should be initialized")
	}

	if e.Findings == nil {
		t.Error("Findings should be initialized")
	}
}

func TestExtractor_PrepareInput_NonExistent(t *testing.T) {
	e := NewExtractor()
	ctx := context.Background()

	_, err := e.PrepareInput(ctx, "/nonexistent/path/test.apk")
	if err == nil {
		t.Error("PrepareInput() should error for non-existent path")
	}
}

func TestExtractor_PrepareInput_ContextCanceled(t *testing.T) {
	tempDir := t.TempDir()

	e := NewExtractor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := e.PrepareInput(ctx, tempDir)
	if err == nil {
		t.Error("PrepareInput() should error when context is canceled")
	}
}

func TestExtractor_PrepareInput_ContextTimeout(t *testing.T) {
	tempDir := t.TempDir()

	e := NewExtractor()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout

	_, err := e.PrepareInput(ctx, tempDir)
	if err == nil {
		t.Error("PrepareInput() should error when context times out")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS POLICY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalysisPolicy_Defaults(t *testing.T) {
	policy := AnalysisPolicy{}

	if policy.FailOnHighRisk {
		t.Error("default FailOnHighRisk should be false")
	}
}

func TestAnalysisPolicy_FailOnHighRisk(t *testing.T) {
	policy := AnalysisPolicy{
		FailOnHighRisk: true,
	}

	if !policy.FailOnHighRisk {
		t.Error("FailOnHighRisk should be true")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INPUT TYPE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestInputType_String(t *testing.T) {
	tests := []struct {
		name     string
		input    InputType
		expected string
	}{
		{"unknown", InputTypeUnknown, "Unknown"},
		{"directory", InputTypeDirectory, "Directory"},
		{"apk file", InputTypeAPKFile, "APKFile"},
		{"dex file", InputTypeDEXFile, "DEXFile"},
		{"archive file", InputTypeArchiveFile, "ArchiveFile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.String()
			if result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARTIFACT FINDING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestArtifactFinding_Creation(t *testing.T) {
	finding := types.ArtifactFinding{
		Severity: types.SeverityHigh,
		Reason:   "Test finding",
		Path:     "/test/path",
	}

	if finding.Severity != types.SeverityHigh {
		t.Errorf("Severity = %q, want %q", finding.Severity, types.SeverityHigh)
	}

	if finding.Reason != "Test finding" {
		t.Errorf("Reason = %q, want %q", finding.Reason, "Test finding")
	}

	if finding.Path != "/test/path" {
		t.Errorf("Path = %q, want %q", finding.Path, "/test/path")
	}
}

func TestArtifactFinding_Severities(t *testing.T) {
	severities := []types.Severity{types.SeverityInfo, types.SeverityMedium, types.SeverityHigh}

	for _, severity := range severities {
		finding := types.ArtifactFinding{
			Severity: severity,
			Reason:   "test",
		}

		if finding.Severity != severity {
			t.Errorf("Severity = %q, want %q", finding.Severity, severity)
		}

		if finding.Reason != "test" {
			t.Errorf("Reason = %q, want %q", finding.Reason, "test")
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECT DIRECTORY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDetectDirectory_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()

	inputType, err := detectDirectory(tempDir)
	if err == nil {
		t.Error("detectDirectory() should error for empty dir")
	}

	if inputType != InputTypeUnknown {
		t.Errorf("detectDirectory() = %v, want %v", inputType, InputTypeUnknown)
	}
}

func TestDetectDirectory_WithSmaliFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create smali directory
	smaliDir := filepath.Join(tempDir, "smali")
	if err := os.MkdirAll(smaliDir, 0755); err != nil {
		t.Fatalf("failed to create smali dir: %v", err)
	}

	// Create a test smali file
	testFile := filepath.Join(smaliDir, "Test.smali")
	if err := os.WriteFile(testFile, []byte(".class public LTest;"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	inputType, err := detectDirectory(tempDir)
	if err != nil {
		t.Fatalf("detectDirectory() error = %v", err)
	}

	if inputType != InputTypeSmaliFolder {
		t.Errorf("detectDirectory() = %v, want %v", inputType, InputTypeSmaliFolder)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECT FILE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDetectFile_ByExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		magic    []byte
		expected InputType
	}{
		{"APK file", "test.apk", magicZIP, InputTypeAPKFile},
		{"DEX file", "classes.dex", magicDEX, InputTypeDEXFile},
		{"ODEX file", "classes.odex", magicODEX, InputTypeDEXFile},
		{"VDEX file", "classes.vdex", magicVDEX, InputTypeDEXFile},
		{"ZIP file", "archive.zip", magicZIP, InputTypeArchiveFile},
		{"XAPK file", "app.xapk", magicZIP, InputTypeAPKFile},
		{"APKS file", "app.apks", magicZIP, InputTypeAPKFile},
		{"APKM file", "app.apkm", magicZIP, InputTypeAPKFile},
		{"AAB file", "app.aab", magicZIP, InputTypeAPKFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			filePath := filepath.Join(tempDir, tt.filename)

			f, err := os.Create(filePath)
			if err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}
			f.Write(tt.magic)
			f.Close()

			inputType, err := detectFile(filePath)
			if err != nil {
				t.Fatalf("detectFile() error = %v", err)
			}

			if inputType != tt.expected {
				t.Errorf("detectFile() = %v, want %v", inputType, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NORMALIZE ARCHIVE TYPE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNormalizeArchiveType_Extensions(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		detected InputType
		expected InputType
	}{
		{"APK extension", "test.apk", InputTypeArchiveFile, InputTypeAPKFile},
		{"XAPK extension", "test.xapk", InputTypeArchiveFile, InputTypeAPKFile},
		{"APKS extension", "test.apks", InputTypeArchiveFile, InputTypeAPKFile},
		{"APKM extension", "test.apkm", InputTypeArchiveFile, InputTypeAPKFile},
		{"AAB extension", "test.aab", InputTypeArchiveFile, InputTypeAPKFile},
		{"ZIP extension", "test.zip", InputTypeArchiveFile, InputTypeArchiveFile},
		{"JAR extension", "test.jar", InputTypeArchiveFile, InputTypeArchiveFile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeArchiveType(tt.path, tt.detected)
			if result != tt.expected {
				t.Errorf("normalizeArchiveType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkNewExtractor(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewExtractor()
	}
}

func BenchmarkDetectInputType_Directory(b *testing.B) {
	tempDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DetectInputType(tempDir)
	}
}

func BenchmarkInputType_String(b *testing.B) {
	inputType := InputTypeAPKFile

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = inputType.String()
	}
}
