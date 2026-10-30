package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestSARIFReporterGenerateIncludesRuleAndSDKRisk(t *testing.T) {
	result := &types.AnalysisResult{
		RuleMatches: []types.Match{{
			SourceLocation: types.SourceLocation{File: "smali/com/app/Main.smali", Line: 42},
			Categorized:    types.Categorized{Category: "DYNAMIC_CODE_LOADING"},
			Scored:         types.Scored{Score: 80},
			Pattern:        "DexClassLoader",
			Context:        "Dynamic code loading",
			Metadata:       map[string]string{"rule_id": "android.dynamic-code", "severity": "high"},
		}},
		FPFilterResults: &types.FPFilterOutput{
			ClassifiedFindings: []types.ClassifiedFinding{{
				Original: &types.Match{
					SourceLocation: types.SourceLocation{File: "smali/okhttp3/Tls.smali", Line: 7},
					Categorized:    types.Categorized{Category: "CRYPTO_WEAK_CIPHER"},
					Pattern:        "CVE-2026-0001 weak cipher",
					Metadata:       map[string]string{"severity": "critical"},
				},
				Verdict:    types.VerdictConfirmedSDKRisk,
				FinalScore: 95,
				SDKInfo:    &types.SDKInfo{Name: "okhttp3", Category: "network", IsKnown: true},
			}},
		},
	}

	dir := t.TempDir()
	if err := NewSARIFReporter(result).Generate(dir); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "analysis.sarif"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("version = %q", log.Version)
	}
	if got := len(log.Runs[0].Results); got != 2 {
		t.Fatalf("results = %d, want 2", got)
	}
	if log.Runs[0].Results[1].Properties["verdict"] != string(types.VerdictConfirmedSDKRisk) {
		t.Fatalf("SDK verdict property missing: %#v", log.Runs[0].Results[1].Properties)
	}
}
