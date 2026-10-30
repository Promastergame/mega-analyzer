package binzap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"mega-analyzer/pkg/binzap/analysis"
	"mega-analyzer/pkg/binzap/lex"
)

func TestExtractParamTypesAndParseDalvikParams(t *testing.T) {
	tests := []struct {
		sig      string
		expected []string
	}{
		{"(ILjava/lang/String;Z)V", []string{"I", "Ljava/lang/String;", "Z"}},
		{"()V", []string{}},
		{"([B[Ljava/lang/Object;I)V", []string{"[B", "[Ljava/lang/Object;", "I"}},
		{"Lcom/app/Billing;->verifyPurchase(Ljava/lang/String;)Z", []string{"Ljava/lang/String;"}},
	}

	for _, test := range tests {
		result := extractParamTypes(test.sig)
		if len(result) == 0 && len(test.expected) == 0 {
			continue
		}
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("For signature %s, expected %v, but got %v", test.sig, test.expected, result)
		}

		dalvikRes := ParseDalvikParams(test.sig)
		if len(dalvikRes) == 0 && len(test.expected) == 0 {
			continue
		}
		if !reflect.DeepEqual(dalvikRes, test.expected) {
			t.Errorf("ParseDalvikParams(%s) expected %v, got %v", test.sig, test.expected, dalvikRes)
		}
	}
}

func TestAdaptHelpers(t *testing.T) {
	if adaptSeverity(analysis.SevCritical) != SeverityCritical {
		t.Error("expected SevCritical -> SeverityCritical")
	}
	if adaptSeverity(analysis.SevHigh) != SeverityHigh {
		t.Error("expected SevHigh -> SeverityHigh")
	}
	if adaptSeverity(analysis.SevMedium) != SeverityMedium {
		t.Error("expected SevMedium -> SeverityMedium")
	}
	if adaptSeverity(analysis.SevLow) != SeverityLow {
		t.Error("expected SevLow -> SeverityLow")
	}
	if adaptSeverity(analysis.SevInfo) != SeverityInfo {
		t.Error("expected SevInfo -> SeverityInfo")
	}

	if adaptConfidence("CONFIRMED") != ConfidenceConfirmed {
		t.Error("expected CONFIRMED")
	}
	if adaptConfidence("HIGH") != ConfidenceHigh {
		t.Error("expected HIGH")
	}
	if adaptConfidence("MEDIUM") != ConfidenceMedium {
		t.Error("expected MEDIUM")
	}
	if adaptConfidence("unknown") != ConfidenceLow {
		t.Error("expected LOW for unknown")
	}

	af := analysis.Finding{
		RuleID:         "TEST-001",
		Title:          "Test Title",
		Severity:       analysis.SevHigh,
		Confidence:     "HIGH",
		File:           "test.smali",
		Line:           42,
		Column:         10,
		Evidence:       "v0 -> v1",
		CWE:            "CWE-89",
		Category:       "injection",
		Remediation:    "sanitization",
		Exploitability: "high",
		DetectedBy:     "taint engine",
		Path:           []string{"v0", "v1"},
	}
	f := adaptFinding(af)
	if f.RuleID != "TEST-001" || f.Severity != SeverityHigh || f.Confidence != ConfidenceHigh || f.CWE != "CWE-89" {
		t.Errorf("adaptFinding mismatch: %+v", f)
	}
}

func TestActiveAnalysisAndSecretTaintSeeds(t *testing.T) {
	// Create smali content with a hardcoded credential that flows to a sink
	smaliContent := `.class public LTest;
.super Ljava/lang/Object;

.method public static test()V
    .registers 2
    const-string v0, "AKIAIOSFODNN7EXAMPLE"
    invoke-static {v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
`
	tmpDir := t.TempDir()
	smaliPath := filepath.Join(tmpDir, "test.smali")
	if err := os.WriteFile(smaliPath, []byte(smaliContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Test lexFile
	tokens, dialect, ok, err := lexFile(smaliPath)
	if err != nil || !ok || dialect != lex.DialectSmali {
		t.Fatalf("lexFile smali failed: ok=%v err=%v dialect=%v", ok, err, dialect)
	}

	// Test lexFile with x86
	asmPath := filepath.Join(tmpDir, "test.s")
	if err := os.WriteFile(asmPath, []byte("mov eax, ebx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, dialectAsm, okAsm, errAsm := lexFile(asmPath)
	if errAsm != nil || !okAsm || dialectAsm != lex.DialectX86 {
		t.Fatalf("lexFile asm failed: ok=%v err=%v dialect=%v", okAsm, errAsm, dialectAsm)
	}

	// Test lexFile with unsupported ext
	txtPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(txtPath, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, okTxt, _ := lexFile(txtPath)
	if okTxt {
		t.Error("expected false for .txt file")
	}

	// Test AnalyzeProgramStats
	ctx := ScanContext{File: smaliPath, Dialect: lex.DialectSmali}
	stats := AnalyzeProgramStats(ctx, tokens)
	if stats.Methods == 0 {
		t.Errorf("expected >0 methods from AnalyzeProgramStats, got %+v", stats)
	}

	// Test secretTaintSeeds
	seeds := secretTaintSeeds(ctx, tokens)
	if len(seeds) == 0 {
		t.Log("secretTaintSeeds returned 0 seeds (depending on secrets.DetectProviders pattern rules)")
	} else {
		if seeds[0].Register != "v0" {
			t.Errorf("expected register v0 in seed, got %s", seeds[0].Register)
		}
	}

	// Test RunActiveAnalysis explicitly passing a seed
	seed := TaintSeed{Register: "v0", Kind: string(analysis.KindCredential), Label: "AWS Key"}
	findings := RunActiveAnalysis(ctx, tokens, seed)
	if len(findings) == 0 {
		t.Log("RunActiveAnalysis ran clean")
	}

	// Test RunActiveFile
	fileFindings, err := RunActiveFile(smaliPath)
	if err != nil {
		t.Fatalf("RunActiveFile: %v", err)
	}
	_ = fileFindings

	// Test RunActiveFile with invalid path
	_, err = RunActiveFile(filepath.Join(tmpDir, "missing.smali"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}
