package pipeline

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
)

func TestNativeDexStringsRemainInventoryThroughTriage(t *testing.T) {
	for _, marker := range []string{"DexClassLoader", "InMemoryDexClassLoader", "classes.dex", "/dex/"} {
		for _, abi := range []string{"x86_64", "arm64"} {
			t.Run(marker+"/"+abi, func(t *testing.T) {
				file := "assets\\vwwwwwvwww\\" + abi + "\\libdpt.so"
				content := []byte("\x7fELF\x00\x00\n\x00" + marker + "\x00")
				ctx := newTestContext(file, content, types.FileTypeNative)
				analysis := types.NewFileAnalysis(file, types.FileTypeNative, int64(len(content)))
				d := NewThreatIndicatorsDetector()
				d.Detect(ctx, analysis)
				result := types.NewAnalysisResult("fixture")
				result.Files[file] = analysis
				p := &Pipeline{result: result}
				p.triageFindings()
				p.buildTypedFindings()
				if !d.GetAggregator().GetSignals().Files[file].Has(SignalNativeDexLoader) {
					t.Fatal("native loader signal was lost")
				}
				if len(result.Findings) != 1 {
					t.Fatalf("findings = %+v", result.Findings)
				}
				f := result.Findings[0]
				if f.Kind != finding.KindInventory || f.Severity != "info" || f.Explanation == nil || f.Explanation.Status != "observation" {
					t.Fatalf("native string became a malware verdict: %+v", f)
				}
				ev := f.Evidence[0]
				if ev.Snippet != marker || ev.Type != "native_string" || ev.Location.Line != 0 || ev.Location.File != file {
					t.Fatalf("original native bytes or location lost: %+v", ev)
				}
				offset := fmt.Sprintf("0x%x", bytes.Index(content, []byte(marker)))
				if !strings.Contains(f.Explanation.Summary, offset) || len(f.Explanation.NextChecks) < 2 || analysis.Matches[0].ReasonForSeverity == "Standard heuristic match." {
					t.Fatalf("native context lost in triage: %+v", f.Explanation)
				}
				if profile := rating.ComputeResultProfile(result); profile.OverallScore != 0 {
					t.Fatalf("string inventory increased risk: %+v", profile)
				}
			})
		}
	}
}

func TestNativeDexInventoryDoesNotSuppressOtherNativeIndicators(t *testing.T) {
	content := []byte("\x7fELF\x00DexClassLoader\x00frida\x00discord.com/api/webhooks\x00")
	ctx := newTestContext("assets/libunknown.so", content, types.FileTypeNative)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	NewThreatIndicatorsDetector().Detect(ctx, analysis)
	for _, m := range analysis.Matches {
		if m.Text == "ANTI_ANALYSIS+PAYLOAD" {
			return
		}
	}
	t.Fatal("native co-occurrence indicator was lost")
}

func TestNativeStringOffsetsUseOriginalBytes(t *testing.T) {
	for _, prefix := range []string{"\x7fELF\x00\u212a\x00", "\x7fELF\x00\u023a\x00"} {
		for _, marker := range []string{"DexClassLoader", "DEXCLASSLOADER", "dexclassloader"} {
			content := []byte(prefix + marker + "\x00")
			ctx := newTestContext("lib.so", content, types.FileTypeNative)
			analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
			NewThreatIndicatorsDetector().Detect(ctx, analysis)
			if len(analysis.Matches) != 1 || analysis.Matches[0].Evidence[0].Snippet != marker ||
				!strings.Contains(analysis.Matches[0].Explanation.Summary, fmt.Sprintf("0x%x", len([]byte(prefix)))) {
				t.Fatalf("Unicode case conversion shifted native evidence: %+v", analysis.Matches)
			}
		}
	}
}

func TestTriagePreservesDetectorEvidenceContext(t *testing.T) {
	result := types.NewAnalysisResult("fixture")
	result.Files["fixture"] = &types.FileAnalysis{Path: "fixture", Matches: []types.Match{{
		EvidenceType: "verified_structure", Confidence: "low", ReasonForSeverity: "Detector supplied context",
		FalsePositiveHints: "Known ambiguity", RequiredNextEvidence: "Check input origin",
	}}}
	(&Pipeline{result: result}).triageFindings()
	m := result.Files["fixture"].Matches[0]
	if m.EvidenceType != "verified_structure" || m.Confidence != "low" || m.ReasonForSeverity != "Detector supplied context" ||
		m.FalsePositiveHints != "Known ambiguity" || m.RequiredNextEvidence != "Check input origin" {
		t.Fatalf("triage overwrote detector context with defaults: %+v", m)
	}
}
