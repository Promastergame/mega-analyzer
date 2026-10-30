package report

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestEvidenceGraphHTMLIsEscapedAndLinked(t *testing.T) {
	result := types.NewAnalysisResult("app")
	result.EvidenceGraph = &types.EvidenceGraph{Version: "1", Nodes: []types.EvidenceNode{{ID: "node1", Kind: "file", Label: `<script>alert(1)</script>`, Path: `smali/<bad>.smali`}}}
	html := NewHTMLReporter(result).BuildHTML()
	if strings.Contains(html, `<script>alert(1)</script>`) {
		t.Fatal("evidence label was not escaped")
	}
	if !strings.Contains(html, "Evidence Graph") || !strings.Contains(html, "evidence-node-list") {
		t.Fatal("evidence graph section missing")
	}
}

func TestDeobfuscationMarkdownShowsBoundedEmulatorOutcome(t *testing.T) {
	result := types.NewAnalysisResult("app")
	result.Deobfuscation = &types.DeobfuscationResult{
		MethodsConsidered: 1, EmulatorAttempts: 1, EmulatorRecoveries: 1, RecoveredStrings: 1,
		Methods: []types.DeobfMethod{{
			ClassName: "Lx/D;", MethodName: "decrypt", CandidateScore: 3,
			Emulation:       &types.DeobfEmulation{Status: "recovered"},
			RecoveredValues: []types.DeobfRecoveredValue{{Value: "https://c2.example", Proof: "bounded execution"}},
		}},
	}
	md := NewMarkdownReporter(result).WithOptions(FullReportOptions()).BuildMarkdown()
	if !strings.Contains(md, "Bounded Dalvik emulator") || !strings.Contains(md, "recovered 1 value") || !strings.Contains(md, "https://c2.example") {
		t.Fatalf("emulator report missing:\n%s", md)
	}
}

func TestNilEvidenceGraphDoesNotRenderSection(t *testing.T) {
	html := NewHTMLReporter(types.NewAnalysisResult("app")).BuildHTML()
	if strings.Contains(html, `id="evidence-graph"`) {
		t.Fatal("nil evidence graph rendered")
	}
}
