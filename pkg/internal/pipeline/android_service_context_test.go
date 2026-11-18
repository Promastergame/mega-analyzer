package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
)

func serviceContextResult(t *testing.T, manifest string, class *types.SmaliClass, extra ...*types.SmaliClass) *types.AnalysisResult {
	t.Helper()
	dir := t.TempDir()
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result := types.NewAnalysisResult(dir)
	result.TargetDir = dir
	file := "smali/Collector.smali"
	m := newMatch(types.CategoryManifestInfo, file, 10, "Service API reference", "api-reference", false)
	m.Severity = types.SeverityInfo
	m.Metadata = map[string]string{"finding_kind": "inventory"}
	result.Files[file] = &types.FileAnalysis{Path: file, SmaliClass: class, Matches: []types.Match{m}}
	for i, child := range extra {
		path := filepath.Join("smali", string(rune('A'+i))+"Child.smali")
		result.Files[path] = &types.FileAnalysis{Path: path, SmaliClass: child}
	}
	return result
}

func TestServiceAPIObservationsDescribeActualManifestContext(t *testing.T) {
	const head = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">`
	const listener = `<service android:name=".Collector" android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"`
	class := &types.SmaliClass{Name: "Lcom/example/Collector;", SuperClass: "Landroid/service/notification/NotificationListenerService;"}
	for _, tc := range []struct {
		name, manifest, condition, limitation string
		wantEvidence                          bool
	}{
		{"missing_service", head + `<application/></manifest>`, "no matching", "callback reachability", false},
		{"permission_only", head + `<uses-permission android:name="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"/><application/></manifest>`, "no matching", "callback reachability", false},
		{"binding_missing", head + `<application><service android:name=".Collector"/></application></manifest>`, "binding permission not verified", "BIND_NOTIFICATION_LISTENER_SERVICE", false},
		{"declared", head + `<application>` + listener + `/></application></manifest>`, "com.example.Collector; enabled=true", "does not establish lifecycle activation", true},
		{"disabled", head + `<application>` + listener + ` android:enabled="false"/></application></manifest>`, "enabled=false", "Code can enable it later", true},
		{"resource_enabled", head + `<application>` + listener + ` android:enabled="@bool/listener_enabled"/></application></manifest>`, "enabled=@bool", "enabled value is unresolved", true},
		{"wrong_namespace", `<manifest xmlns:android="urn:wrong" package="com.example"><application>` + listener + `/></application></manifest>`, "unknown", "could not be verified", false},
		{"truncated", head + `<application>` + listener + `/>`, "unknown", "could not be verified", false},
		{"unavailable", "", "unknown", "could not be verified", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := serviceContextResult(t, tc.manifest, class)
			(&Pipeline{result: result}).buildTypedFindings()
			if len(result.Findings) != 1 {
				t.Fatalf("findings=%+v", result.Findings)
			}
			item := result.Findings[0]
			if item.Kind != finding.KindInventory || item.Severity != "info" || item.Explanation == nil {
				t.Fatalf("service context changed API observation into a risk: %+v", item)
			}
			if !strings.Contains(strings.Join(item.Explanation.Conditions, "\n"), tc.condition) ||
				!strings.Contains(strings.Join(item.Explanation.Limitations, "\n"), tc.limitation) {
				t.Fatalf("manifest context missing: %+v", item.Explanation)
			}
			hasDeclaration := false
			for _, evidence := range item.Evidence {
				if evidence.Type == "manifest_service_declaration" {
					hasDeclaration = evidence.Location.File == filepath.Join(result.TargetDir, "AndroidManifest.xml") &&
						evidence.Location.Line > 0 && strings.Contains(evidence.Snippet, "<service")
				}
			}
			if hasDeclaration != tc.wantEvidence {
				t.Fatalf("declaration evidence=%t, want %t: %+v", hasDeclaration, tc.wantEvidence, item.Evidence)
			}
			if rating.ComputeResultProfile(result).OverallScore != 0 {
				t.Fatal("service declaration increased the risk of an API observation")
			}
		})
	}
}

func TestServiceContextRecognizesDeclaredSubclassAndAlternatePrefix(t *testing.T) {
	base := &types.SmaliClass{Name: "Lcom/code/BaseListener;", SuperClass: "Landroid/service/notification/NotificationListenerService;"}
	child := &types.SmaliClass{Name: "Lcom/code/ChildListener;", SuperClass: base.Name}
	manifest := `<manifest xmlns:a="http://schemas.android.com/apk/res/android" package="com.changed"><application><service a:name="com.code.ChildListener" a:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"/></application></manifest>`
	result := serviceContextResult(t, manifest, base, child)
	(&Pipeline{result: result}).buildTypedFindings()
	item := result.Findings[0]
	if !strings.Contains(strings.Join(item.Explanation.Conditions, "\n"), "com.code.ChildListener; enabled=true") {
		t.Fatalf("declared subclass or full class namespace lost: %+v", item.Explanation)
	}
}

func TestMissingServiceDoesNotSuppressIndependentRisks(t *testing.T) {
	class := &types.SmaliClass{Name: "Lcom/example/Collector;", SuperClass: "Landroid/app/Service;"}
	for _, kind := range []string{"vulnerability", "malware"} {
		t.Run(kind, func(t *testing.T) {
			result := serviceContextResult(t, `<manifest package="com.example"><application/></manifest>`, class)
			m := &result.Files["smali/Collector.smali"].Matches[0]
			m.Metadata["finding_kind"] = kind
			m.Category, m.Severity, m.Score = types.CategoryHardcodedSecret, types.SeverityHigh, 80
			(&Pipeline{result: result}).buildTypedFindings()
			if result.Findings[0].Kind != finding.Kind(kind) || result.Findings[0].Severity != "high" {
				t.Fatalf("missing lifecycle declaration suppressed an independent finding: %+v", result.Findings[0])
			}
		})
	}
}

func TestServiceContextDoesNotMutateRetainedExplanation(t *testing.T) {
	result := serviceContextResult(t, `<manifest package="com.example"><application/></manifest>`,
		&types.SmaliClass{Name: "Lcom/example/Collector;", SuperClass: "Landroid/app/Service;"})
	raw := &result.Files["smali/Collector.smali"].Matches[0]
	raw.Explanation = &finding.Explanation{Status: "observation", Limitations: []string{"Original limitation"}}
	RefreshTypedFindings(result)
	RefreshTypedFindings(result)
	if len(raw.Explanation.Limitations) != 1 || len(raw.Explanation.Conditions) != 0 {
		t.Fatalf("retained source explanation mutated: %+v", raw.Explanation)
	}
	if len(result.Findings) != 1 || result.Findings[0].Occurrences != 1 {
		t.Fatalf("repeated refresh duplicated the observation: %+v", result.Findings)
	}
}

func TestServiceDescriptorKeepsLeadingLInJavaNames(t *testing.T) {
	if got := serviceClassDescriptor("Legacy.package.Listener"); got != "Legacy/package/Listener" {
		t.Fatalf("Java name was confused with a descriptor: %s", got)
	}
}
