package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func TestFindingExplanationsKeepEvidenceAndEscapeAPKText(t *testing.T) {
	result := types.NewAnalysisResult("sample.apk")
	item := finding.FromLegacy(finding.LegacyInput{RuleID: "review.pending_flags", Kind: finding.KindInventory, Severity: "info", Title: "Flags unresolved", Evidence: `<script>alert('apk')</script>`, Location: finding.Location{File: "Intent.smali", Line: 42}})
	item.Explanation = &finding.Explanation{Status: "needs_review", Summary: "Mutability is unknown", Conditions: []string{"flags register unresolved"}, Limitations: []string{"not a confirmed vulnerability"}, NextChecks: []string{"inspect callers"}}
	result.Findings = []finding.Finding{item}
	view := NewViewBuilder(result, DefaultOptions()).Build()
	html := NewHTMLReporter(result).BuildHTML()
	md := NewMarkdownRenderer(DefaultOptions()).Render(view)
	for name, text := range map[string]string{"HTML": html, "Markdown": md} {
		if !strings.Contains(text, "Finding explanations") || !strings.Contains(text, "needs_review") || !strings.Contains(text, "inspect callers") || !strings.Contains(text, "Intent.smali:42") {
			t.Fatalf("%s lost explanation or evidence location", name)
		}
		if strings.Contains(text, `<script>alert('apk')</script>`) || !strings.Contains(text, "&lt;script&gt;") {
			t.Fatalf("%s treated APK text as markup", name)
		}
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var decoded finding.Finding
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.Explanation == nil || decoded.Explanation.Status != "needs_review" || decoded.Evidence[0].Digest != item.Evidence[0].Digest {
		t.Fatalf("JSON explanation/evidence contract lost: %v", err)
	}
}

func TestFindingBinaryEvidenceExportsAsUTF8WithoutChangingEvidence(t *testing.T) {
	result := types.NewAnalysisResult("sample.apk")
	raw := "\x7fELF\x00\xff" + strings.Repeat("\x00\x80", 4096)
	item := finding.FromLegacy(finding.LegacyInput{RuleID: "binary.reference", Kind: finding.KindInventory, Severity: "info",
		Title: strings.Repeat("Ж", 100), Evidence: raw, Location: finding.Location{File: "lib/test.so", Line: 1}})
	item.Description = raw
	item.Evidence[0].Description = raw
	item.Explanation = &finding.Explanation{Status: "heuristic", Summary: "Standard heuristic match.\n" + raw,
		Conditions: []string{raw}, Limitations: []string{raw}, NextChecks: []string{raw}}
	result.Findings = []finding.Finding{item}
	reporter := NewMarkdownReporter(result)
	var stream bytes.Buffer
	if err := reporter.GenerateStream(&stream); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := reporter.Generate(dir); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"HTML": NewHTMLReporter(result).BuildHTML(), "Markdown": reporter.BuildMarkdown(), "Stream": stream.String(), "File": string(file)} {
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || !strings.Contains(text, "Binary evidence") || !strings.Contains(text, "7f 45 4c 46 00 ff") {
			t.Fatalf("%s emitted raw binary or lost its readable byte preview", name)
		}
		if !strings.Contains(text, "inspect the original artifact") {
			t.Fatalf("%s did not bound binary evidence previews", name)
		}
	}
	if result.Findings[0].Evidence[0].Snippet != raw || result.Findings[0].Evidence[0].Digest != item.Evidence[0].Digest ||
		result.Findings[0].Description != raw || result.Findings[0].Evidence[0].Description != raw || result.Findings[0].Explanation.Summary != "Standard heuristic match.\n"+raw {
		t.Fatal("report rendering changed the structured evidence")
	}
}

func TestMarkdownUnicodeRuleDescriptionsRemainValid(t *testing.T) {
	rule := RuleFindingView{Name: strings.Repeat("Ж", 80), Description: strings.Repeat("Ю", 80), Severity: "high"}
	view := ReportView{RuleFindings: []RuleFindingView{rule}, BankingThreats: []RuleFindingView{rule}}
	if text := NewMarkdownRenderer(DefaultOptions()).Render(view); !utf8.ValidString(text) || !strings.Contains(text, "Ж") || !strings.Contains(text, "Ю") {
		t.Fatal("Markdown truncation corrupted a Unicode rule title or description")
	}
}
