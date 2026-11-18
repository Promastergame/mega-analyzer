package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func TestAmbiguousDispatchDoesNotAssertLoaderVulnerability(t *testing.T) {
	flow := types.DataFlowFinding{Source: "Landroid/content/Intent;->getStringExtra", Sink: "Ljava/lang/Class;->forName", Category: "dynamic_class_loading", Severity: "high", Confidence: 0.96,
		Location: types.SourceLocation{File: "smali/androidx/Example.smali"}}
	for _, ambiguous := range []bool{false, true} {
		flow.Path = nil
		if ambiguous {
			flow.Path = []types.DataFlowStep{{Type: "unresolved_dispatch"}}
		}
		p := &Pipeline{result: &types.AnalysisResult{Files: map[string]*types.FileAnalysis{flow.Location.File: {IsAppCode: false}}, DataFlows: []types.DataFlowFinding{flow}}}
		p.buildTypedFindings()
		item := p.result.Findings[0]
		if ambiguous && (item.Kind != finding.KindInventory || item.Severity != "info" || item.Explanation.Status != "unresolved_dispatch") {
			t.Fatalf("unresolved path asserted: %+v", item)
		}
		if !ambiguous && (item.Kind != finding.KindVulnerability || item.Severity != "high") {
			t.Fatalf("real external path hidden by library namespace: %+v", item)
		}
	}
}

func TestBackupDeclarationDoesNotProveExtraction(t *testing.T) {
	for _, target := range []string{"28", "35"} {
		matches := runManifestDetect(t, `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.backup"><uses-sdk android:targetSdkVersion="`+target+`"/><application android:allowBackup="true"/></manifest>`)
		found := false
		for _, match := range matches {
			if match.Category != types.CategoryInsecureBackup {
				continue
			}
			found = true
			item := typedFindingFromMatch(match, "")
			if item.Kind != finding.KindInventory || item.Severity != "info" || len(item.Explanation.Limitations) == 0 {
				t.Fatalf("backup overclaimed: %+v", item)
			}
		}
		if !found {
			t.Fatal("backup observation lost")
		}
	}
}
