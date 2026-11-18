package report

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/sourceevidence"
	"mega-analyzer/pkg/internal/types"
)

func reviewFixture() (*types.AnalysisResult, finding.Finding, finding.Finding) {
	r := types.NewAnalysisResult("F:\\fixture")
	a := finding.FromLegacy(finding.LegacyInput{RuleID: "fixture.rule", Kind: finding.KindVulnerability, Severity: "high", Title: "Shared title",
		Location: finding.Location{File: "smali/x/A.smali", Line: 42, Class: "x.A", Method: "a"}, Evidence: "use v0"})
	b := finding.FromLegacy(finding.LegacyInput{RuleID: "fixture.rule", Kind: finding.KindVulnerability, Severity: "high", Title: "Shared title",
		Location: finding.Location{File: "smali/y/A.smali", Line: 42, Class: "y.A", Method: "a"}, Evidence: "use v0"})
	r.Findings = []finding.Finding{a, b}
	r.Files["smali/x/A.smali"] = &types.FileAnalysis{Path: "smali/x/A.smali", SmaliClass: &types.SmaliClass{Name: "x.A", Methods: []types.SmaliMethod{{Name: "a", Params: "I", ReturnType: "V"}}}}
	r.Files["smali/y/A.smali"] = &types.FileAnalysis{Path: "smali/y/A.smali", SmaliClass: &types.SmaliClass{Name: "y.A", Methods: []types.SmaliMethod{{Name: "a", Params: "I", ReturnType: "V"}}}}
	source := sourceevidence.NewReport()
	source.Checks = []sourceevidence.Check{{ID: "source-one", Kind: "path_origin", Method: "Lx/A;->a(I)V", Status: "supported", Choice: "application_data_dir",
		Summary: "</p><script>untrusted()</script>", Citations: []sourceevidence.Citation{{File: "F:\\fixture\\smali\\x\\A.smali", Method: "Lx/A;->a(I)V", Line: 42, Snippet: "const/4 v0, 0x1"}}}}
	r.SourceEvidence = &source
	r.GNNDiagnostics = &types.GNNDiagnostics{Status: "complete", Methods: []types.GNNMethodDiagnostic{{File: "smali/x/A.smali", Method: "x.A->a(I)V", Status: "predicted", PredictedClass: "benign"}}}
	score := .5
	r.DecisionAI = &decisionai.Report{Status: "complete", Entries: []decisionai.Entry{{FindingID: a.ID, Fingerprint: a.Fingerprint, RuleID: a.RuleID, ReviewRoute: "human",
		Response: decisionai.Response{Version: "fixture", Backend: "experts", Answers: map[string]decisionai.Answer{"false_positive": {Source: "finding-rule", Noul: &score}}}}},
		SourceReview: &decisionai.SourceReviewReport{Entries: []decisionai.SourceReviewEntry{{CheckID: "source-one", Kind: "path_origin", SourceConsistent: false, ReviewRoute: "human", Reason: "service_answer_not_supported_by_source_contract",
			Response: decisionai.Response{Answers: map[string]decisionai.Answer{"source_check": {Source: "source-evidence-rule", Choice: "unresolved"}}}}}},
		CodeReview: &decisionai.CodeReviewReport{Entries: []decisionai.CodeReviewEntry{{File: "smali/x/A.smali", Method: "Lx/A;->a(I)V", Line: 42, Literal: "0x1", Status: "skipped", Reason: "no_retained_value_use"}}}}
	return r, a, b
}

func TestFindingCardsBindByIdentityAndExactMethod(t *testing.T) {
	r, a, b := reviewFixture()
	before := decisionai.FindingSnapshotSHA256(r.Findings)
	view := NewViewBuilder(r, DefaultOptions()).Build()
	index := NewHTMLReporter(r).findingReviews(view.TypedFindings)
	first := index.items[a.ID+"\x00"+a.Fingerprint]
	second := index.items[b.ID+"\x00"+b.Fingerprint]
	if len(first.decisions) != 1 || len(first.checks) != 1 || len(first.graphs) != 1 || len(first.roles) != 1 {
		t.Fatalf("exact finding lost linked reviews: %+v", first)
	}
	if len(second.decisions)+len(second.checks)+len(second.graphs)+len(second.roles) != 0 {
		t.Fatal("shared title/basename linked another file's analysis")
	}
	output := NewHTMLReporter(r).BuildHTML()
	for _, section := range []string{`id="decision-ai"`, `id="source-evidence"`, `id="gnn-coverage"`} {
		if strings.Contains(output, section) {
			t.Fatal("standalone review section retained")
		}
	}
	for _, text := range []string{"DecisionAI · scanner rules", "Related static source checks", "Neural protection classifier", "Neural roles of constants in this method", "service_answer_not_supported_by_source_contract", "Neural prediction not produced"} {
		if !strings.Contains(output, text) {
			t.Fatalf("finding lost review provenance: %s", text)
		}
	}
	if strings.Contains(output, "<script>untrusted()") || !strings.Contains(output, "&lt;script&gt;") {
		t.Fatal("untrusted source became markup")
	}
	if before != decisionai.FindingSnapshotSHA256(r.Findings) {
		t.Fatal("rendering changed canonical findings")
	}
}

func TestAmbiguousMethodsAndMinifiedComponentsStayUnlinked(t *testing.T) {
	r, a, _ := reviewFixture()
	r.Files["smali/x/A.smali"].SmaliClass.Methods = append(r.Files["smali/x/A.smali"].SmaliClass.Methods, types.SmaliMethod{Name: "a", Params: "J", ReturnType: "V"})
	view := NewViewBuilder(r, DefaultOptions()).Build()
	index := NewHTMLReporter(r).findingReviews(view.TypedFindings)
	links := index.items[a.ID+"\x00"+a.Fingerprint]
	if len(links.checks)+len(links.graphs)+len(links.roles) != 0 || len(links.decisions) != 1 {
		t.Fatal("simple name joined overloaded methods or broke exact finding identity")
	}
	component := finding.FromLegacy(finding.LegacyInput{RuleID: "fixture.component", Kind: finding.KindInventory, Title: "Manifest", Location: finding.Location{File: "AndroidManifest.xml", Line: 1}})
	r.Findings = []finding.Finding{component}
	r.SourceEvidence.Checks = []sourceevidence.Check{
		{Kind: "component_surface", Method: "x.One", Citations: []sourceevidence.Citation{{File: "AndroidManifest.xml", Line: 1}}},
		{Kind: "component_surface", Method: "x.Two", Citations: []sourceevidence.Citation{{File: "AndroidManifest.xml", Line: 1}}},
	}
	view = NewViewBuilder(r, DefaultOptions()).Build()
	index = NewHTMLReporter(r).findingReviews(view.TypedFindings)
	if len(index.items[component.ID+"\x00"+component.Fingerprint].checks) != 0 {
		t.Fatal("one minified manifest line confirmed every component")
	}
}

func TestFindingReviewAbstentionDoesNotDisplayNeutralScore(t *testing.T) {
	for _, abstained := range []bool{true, false} {
		r, _, _ := reviewFixture()
		a := r.DecisionAI.Entries[0].Response.Answers["false_positive"]
		a.Abstained, a.Reason = abstained, "unlinked_behavior_evidence"
		r.DecisionAI.Entries[0].Response.Answers["false_positive"] = a
		output := NewHTMLReporter(r).BuildHTML()
		if strings.Contains(output, "Advisory false-positive score: 0.5000") == abstained {
			t.Fatalf("score visibility disagrees with abstained=%t", abstained)
		}
		if abstained && (!strings.Contains(output, "False-positive score unavailable") || !strings.Contains(output, "unlinked_behavior_evidence")) {
			t.Fatal("abstention reason or unavailable score was lost")
		}
		if !strings.Contains(output, "No neural model was called for this finding review") {
			t.Fatal("scanner-rule review did not explain its model usage")
		}
		if *r.DecisionAI.Entries[0].Response.Answers["false_positive"].Noul != .5 {
			t.Fatal("rendering changed the wire response")
		}
	}
}
