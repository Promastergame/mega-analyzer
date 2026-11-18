package pipeline

import (
	"context"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/internal/types"
)

func TestNativeDictionaryDoesNotProducePayload(t *testing.T) {
	d := NewThreatIndicatorsDetector()
	content := []byte("\x7fELF pragmafridayjuniordollar clearlyexposedBrowser http://dictionary.example")
	ctx := newTestContext("lib/renamed.so", content, types.FileTypeNative)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	if len(analysis.Matches) != 0 {
		t.Fatalf("dictionary text produced threat matches: %+v", analysis.Matches)
	}
	content = []byte("\x7fELF friday exposed\x00checking for frida-agent\x00discord.com/api/webhooks")
	ctx = newTestContext("lib/renamed.so", content, types.FileTypeNative)
	analysis = types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	for _, m := range analysis.Matches {
		if m.Text == "ANTI_ANALYSIS+PAYLOAD" {
			return
		}
	}
	t.Fatal("real payload after misleading dictionary matches was lost")
}

func TestPathConstructionIsInventoryButFileAccessIsReviewed(t *testing.T) {
	flow := types.DataFlowFinding{Category: "path_traversal", Severity: "high", Confidence: 0.99, Sink: "Ljava/io/File;-><init>(Ljava/lang/String;)V"}
	got := typedFindingFromDataFlow(flow, nil)
	if got.Kind != finding.KindInventory || got.Severity != "info" || len(got.CWE) != 0 {
		t.Fatalf("path construction reported a vulnerability: %+v", got)
	}
	flow.Sink = "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
	got = typedFindingFromDataFlow(flow, nil)
	if got.Kind != finding.KindVulnerability || got.Severity != "high" {
		t.Fatalf("actual I/O path was lost: %+v", got)
	}
}

func TestURLConstructionAndUnresolvedLoadAreObservations(t *testing.T) {
	for _, sink := range []string{"Ljava/net/URL;-><init>(Ljava/lang/String;)V", "Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;"} {
		got := typedFindingFromDataFlow(types.DataFlowFinding{Category: "ssrf", Severity: "high", Confidence: 0.99, Sink: sink}, nil)
		if got.Kind != finding.KindInventory || got.Severity != "info" {
			t.Errorf("URL builder is not a request: %+v", got)
		}
	}
	for _, pattern := range []string{"System.load computed path", "loadLibrary computed name"} {
		got := typedFindingFromMatch(types.Match{Categorized: types.Categorized{Category: types.CategoryDynamicLoad}, Pattern: pattern, Severity: types.SeverityHigh}, "")
		if got.Kind != finding.KindInventory || got.Severity != "info" {
			t.Errorf("unresolved argument claimed an unsafe load: %+v", got)
		}
	}
	got := typedFindingFromMatch(types.Match{Categorized: types.Categorized{Category: types.CategoryDynamicLoad}, Pattern: "System.load external path", Severity: types.SeverityCritical, Metadata: map[string]string{"finding_kind": "vulnerability"}}, "")
	if got.Kind != finding.KindVulnerability || got.Severity != "critical" {
		t.Errorf("proven unsafe loading was lost: %+v", got)
	}
}

func TestNativeSidecarCandidatesDoNotBecomeVulnerabilities(t *testing.T) {
	for _, reason := range []string{"Standalone numeric string, candidate PIN/password", "[import] Process control / anti-debug", "[packing] Elevated entropy", "[anti-analysis] Frida instrumentation reference"} {
		got := typedFindingFromArtifact(types.ArtifactFinding{Reason: reason, Severity: types.SeverityHigh})
		if got.Kind != finding.KindInventory {
			t.Errorf("%s: kind %s", reason, got.Kind)
		}
	}
	got := typedFindingFromArtifact(types.ArtifactFinding{Reason: "Crack point [tamper]: checkSignature", Severity: types.SeverityHigh})
	if got.Kind != finding.KindHardening {
		t.Errorf("protection became %s", got.Kind)
	}
}

func TestCredentialStorageRequiresRawValueAtCredentialKey(t *testing.T) {
	for _, tc := range []struct {
		key, transform string
		want           bool
	}{
		{"password", "", true},
		{"app_password_hash", "", false},
		{"password", "invoke-static {v2}, Lapp/Hash;->sha256(Ljava/lang/String;)Ljava/lang/String;\nmove-result-object v2", false},
		{"theme", "", false},
	} {
		body := []string{"const-string v0, \"" + tc.key + "\"", "invoke-virtual {p0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;", "move-result-object v2", "invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;", "move-result-object v2"}
		if tc.transform != "" {
			body = append(body, "invoke-static {v2}, Lapp/Hash;->sha256(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2")
		}
		body = append(body, "invoke-interface {v1, v0, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;")
		_, got := plaintextCredentialWriteWitness(&types.SmaliMethod{Name: "save", Body: body}, "Config.smali", "app.Config")
		if got != tc.want {
			t.Errorf("key %s, transform %q: proof=%v, want %v", tc.key, tc.transform, got, tc.want)
		}
	}
}

func TestUIFakeClickIsNotPiracy(t *testing.T) {
	inner, err := piracy.NewDetectorFromBytes(configs.PiracySites())
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(".method public static sendFakeClick(Landroid/view/View;)V\nreturn-void\n.end method")
	ctx := newTestContext("smali/app/UI.smali", content, types.FileTypeSmali)
	ctx.Ctx = context.Background()
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	NewPiracyDetectorAdapter(inner).Detect(ctx, analysis)
	if len(analysis.Matches) != 0 {
		t.Fatalf("UI click helper flagged as piracy: %+v", analysis.Matches)
	}
}

func TestInformationalCandidatesAndHTTPReferencesAreInventory(t *testing.T) {
	for _, category := range []types.Category{types.CategoryExportedComponent, types.CategoryDeepLinkVuln, types.CategoryZipSlip} {
		got := typedFindingFromMatch(types.Match{Categorized: types.Categorized{Category: category}, Severity: types.SeverityInfo}, "")
		if got.Kind != finding.KindInventory || len(got.CWE) != 0 || len(got.MASVS) != 0 || got.Explanation.Status != "observation" {
			t.Fatalf("informational candidate became a defect: %+v", got)
		}
	}
	got := typedFindingFromMatch(types.Match{Categorized: types.Categorized{Category: types.CategoryCleartextTraffic}, Pattern: "http://microformats.org/wiki/hcard", Severity: types.SeverityMedium}, "")
	if got.Kind != finding.KindInventory || got.Severity != "info" {
		t.Fatalf("hyperlink became application traffic: %+v", got)
	}
	got = typedFindingFromMatch(types.Match{Categorized: types.Categorized{Category: types.CategoryCleartextTraffic}, Pattern: "usesCleartextTraffic=true", Severity: types.SeverityMedium, Metadata: map[string]string{"finding_kind": "vulnerability"}}, "")
	if got.Kind != finding.KindVulnerability || got.Severity != "medium" {
		t.Fatalf("explicit cleartext policy was lost: %+v", got)
	}
}

func TestPreferenceReadDoesNotProveExternalControl(t *testing.T) {
	flow := types.DataFlowFinding{Category: "path_traversal", Severity: "high", Confidence: 0.95,
		Source: "Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
		Sink:   "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V", ExploitChain: "untrusted_file_to_filesystem_access"}
	got := typedFindingFromDataFlow(flow, nil)
	if got.Kind != finding.KindInventory || got.Severity != "info" || len(got.CWE) != 0 || strings.Contains(got.Title, "Exploit chain") {
		t.Fatalf("app-local storage became an exploit: %+v", got)
	}
	flow.Category = "log_data_exposure"
	flow.Sink = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
	got = typedFindingFromDataFlow(flow, nil)
	if got.Kind != finding.KindVulnerability {
		t.Fatalf("stored sensitive-data exposure was lost: %+v", got)
	}
	flow.Category = "path_traversal"
	flow.Sink = "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
	flow.Source = "Landroid/content/Intent;->getData()Landroid/net/Uri;"
	got = typedFindingFromDataFlow(flow, nil)
	if got.Kind != finding.KindVulnerability || got.Severity != "high" {
		t.Fatalf("external-input I/O candidate was lost: %+v", got)
	}
}

func TestRefreshKeepsCorrectedSidecarSeverityAndLateEvidence(t *testing.T) {
	artifact := types.ArtifactFinding{Path: "lib/example.so", Reason: "[packing] Packed or encrypted payload: likely packed/encrypted", Severity: types.SeverityHigh}
	fresh := typedFindingFromArtifact(artifact)
	stale := fresh
	stale.Kind, stale.Severity = finding.KindVulnerability, "high"
	late := finding.FromLegacy(finding.LegacyInput{RuleID: "other.engine", Kind: finding.KindVulnerability, Severity: "high", Evidence: "independent evidence"})
	result := &types.AnalysisResult{ArtifactFindings: []types.ArtifactFinding{artifact}, Findings: []finding.Finding{stale, late}}
	RefreshTypedFindings(result)
	if len(result.Findings) != 2 {
		t.Fatalf("late evidence lost or duplicate introduced: %+v", result.Findings)
	}
	for _, f := range result.Findings {
		if f.RuleID == fresh.RuleID && (f.Kind != finding.KindInventory || f.Severity != "info" || strings.Contains(f.Title, "Packed or encrypted payload")) {
			t.Fatalf("stale sidecar assessment restored: %+v", f)
		}
	}
}
