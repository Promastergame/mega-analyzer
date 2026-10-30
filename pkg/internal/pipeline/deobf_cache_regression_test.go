package pipeline

// Regression tests for the 2026-09-21 audit findings on the deobfuscation
// content cache: a warm cache must return the same structural findings as a
// cold run, a change of engine options must not be served stale results, and
// a recovered worker panic must stay visible in the published coverage.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func cachedDeobfPipeline(t *testing.T) *Pipeline {
	t.Helper()
	c := config.DefaultConfig()
	c.EnableContentCache = true
	c.ContentCacheDir = filepath.Join(t.TempDir(), "cache")
	p, err := NewPipeline(c)
	if err != nil {
		t.Fatal(err)
	}
	if p.contentCache == nil {
		t.Fatal("content cache unavailable")
	}
	return p
}

// opaquePredicateClass builds a class whose method hides a tautological
// if-eq behind the deobfuscation engine's opaque-predicate pass, with no
// encrypted strings at all.
func opaquePredicateClass() *types.FileAnalysis {
	return &types.FileAnalysis{
		Path: "smali/example/A.smali", Type: types.FileTypeSmali,
		SmaliClass: &types.SmaliClass{Name: "Lexample/A;", Methods: []types.SmaliMethod{{
			Name: "test", Params: "()", ReturnType: "V",
			Body: []string{".locals 1", "const/4 v0, 0x1", "if-eq v0, v0, :yes", "return-void", ":yes", "return-void"},
		}}},
	}
}

func TestWarmCachePreservesStructuralFindings(t *testing.T) {
	p := cachedDeobfPipeline(t)
	cold := opaquePredicateClass()
	p.deobfuscateClass(cold, cold.SmaliClass)
	if cold.Deobfuscation == nil || cold.Deobfuscation.OpaquePredicates == 0 {
		t.Fatalf("fixture did not detect opaque predicate: %+v", cold.Deobfuscation)
	}
	warm := opaquePredicateClass()
	p.deobfuscateClass(warm, warm.SmaliClass)
	if warm.Deobfuscation == nil {
		t.Fatalf("warm cache dropped Deobfuscation entirely (cold opaque=%d)", cold.Deobfuscation.OpaquePredicates)
	}
	if warm.Deobfuscation.OpaquePredicates != cold.Deobfuscation.OpaquePredicates {
		t.Fatalf("cold=%+v warm=%+v", cold.Deobfuscation, warm.Deobfuscation)
	}
	if len(warm.Deobfuscation.Methods) != len(cold.Deobfuscation.Methods) {
		t.Fatalf("warm cache dropped method entries: cold=%+v warm=%+v", cold.Deobfuscation.Methods, warm.Deobfuscation.Methods)
	}
}

func TestCacheRespectsDeobfuscationOptions(t *testing.T) {
	p := cachedDeobfPipeline(t)
	p.config.DeobfuscationOptions.EnableStringDec = false
	cold := smaliClassWithEncryptedURL(t, "Lexample/A;", "https://audit.example/endpoint")
	p.deobfuscateClass(cold, cold.SmaliClass)
	if len(cold.RecoveredStrings) != 0 {
		t.Fatalf("fixture recovered strings with string decoding disabled: %q", cold.RecoveredStrings)
	}
	p.config.DeobfuscationOptions.EnableStringDec = true
	warm := smaliClassWithEncryptedURL(t, "Lexample/A;", "https://audit.example/endpoint")
	p.deobfuscateClass(warm, warm.SmaliClass)
	p.contentCache = nil
	uncached := smaliClassWithEncryptedURL(t, "Lexample/A;", "https://audit.example/endpoint")
	p.deobfuscateClass(uncached, uncached.SmaliClass)
	if len(uncached.RecoveredStrings) == 0 {
		t.Fatal("fixture did not recover strings without cache")
	}
	if len(warm.RecoveredStrings) != len(uncached.RecoveredStrings) {
		t.Fatalf("stale negative result reused after enabling string decoding: warm=%q uncached=%q", warm.RecoveredStrings, uncached.RecoveredStrings)
	}
}

// ── worker panic visibility ──────────────────────────────────────────────────

type panickingDetector struct{}

func (panickingDetector) Name() string { return "panicking-detector" }
func (panickingDetector) Detect(*FileDetectContext, *types.FileAnalysis) {
	panic("injected detector failure")
}

// TestWorkerPanicCountedAsFailedFile pins two properties: a panicking detector
// must not abort the scan (per-file recovery), and the failure must be visible
// in the published coverage instead of hiding in an internal counter.
func TestWorkerPanicCountedAsFailedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sample.txt"), []byte("sample text"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	p.RegisterDetector(panickingDetector{})
	result, err := p.Run(context.Background(), root)
	if err != nil {
		t.Fatalf("per-file detector panic must not fail the scan: %v", err)
	}
	if result == nil {
		t.Fatal("Run returned nil result without error")
	}
	if result.Coverage.FilesFailed != 1 {
		t.Fatalf("Coverage.FilesFailed = %d, want 1 (worker panic not surfaced)", result.Coverage.FilesFailed)
	}
	if result.Coverage.Parsed < 1 {
		t.Fatalf("Coverage.Parsed = %d, want the file counted before detector failure", result.Coverage.Parsed)
	}
}
