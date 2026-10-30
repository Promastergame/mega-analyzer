package pipeline

import (
	"context"
	"encoding/base64"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestClassifyRecoveredTextProducesTypedNetworkArtifacts(t *testing.T) {
	got := classifyRecoveredText("https://c2.example/path", "Lx/A;->d()V", 7, 0)
	kinds := make(map[string]bool)
	for _, artifact := range got {
		kinds[artifact.artifact.Kind] = true
		if artifact.artifact.ID == "" || artifact.artifact.SHA256 == "" {
			t.Fatalf("missing stable identity: %+v", artifact.artifact)
		}
	}
	for _, kind := range []string{"string", "url", "domain"} {
		if !kinds[kind] {
			t.Fatalf("missing %s artifact: %+v", kind, got)
		}
	}
}

func TestClassifyRecoveredTextClassNamesAndReflection(t *testing.T) {
	gotJava := classifyRecoveredText("com.example.malware.PayloadClass", "Lx/A;->decrypt()V", 12, 0)
	kinds := make(map[string]bool)
	for _, a := range gotJava {
		kinds[a.artifact.Kind] = true
	}
	if !kinds["class_name"] || !kinds["reflection_target"] {
		t.Fatalf("expected class_name and reflection_target for Java class string, got %+v", gotJava)
	}

	gotReflect := classifyRecoveredText("java.lang.Class.forName", "Lx/A;->reflect()V", 20, 0)
	hasReflection := false
	for _, a := range gotReflect {
		if a.artifact.Kind == "reflection_target" {
			hasReflection = true
		}
	}
	if !hasReflection {
		t.Fatalf("expected reflection_target for reflection API string, got %+v", gotReflect)
	}
}

func TestRecoveredArtifactDispatcherDedupesAndScansJavaScript(t *testing.T) {
	pipeline := &Pipeline{}
	analysis := types.NewFileAnalysis("classes.dex", types.FileTypeDex, 1)
	js := `function run(){ return eval("fetch('https://c2.example')"); } module.exports=run;`
	analysis.RecoveredStrings = []string{js, js}
	pipeline.dispatchRecoveredArtifacts(context.Background(), analysis, FileJob{RelPath: "classes.dex", Type: types.FileTypeSmali})
	if analysis.RecoveredArtifactSummary == nil || analysis.RecoveredArtifactSummary.Deduped == 0 || analysis.RecoveredArtifactSummary.Scanned == 0 {
		t.Fatalf("dispatcher counters missing: %+v", analysis.RecoveredArtifactSummary)
	}
	foundJS := false
	for _, artifact := range analysis.RecoveredArtifacts {
		if artifact.Kind == "javascript" && artifact.Status == "scanned" {
			foundJS = true
		}
	}
	if !foundJS || len(analysis.Matches) == 0 {
		t.Fatalf("JavaScript was not scanned: artifacts=%+v matches=%+v", analysis.RecoveredArtifacts, analysis.Matches)
	}
}

func TestDecodeRecognizedRecoveredPayloadRejectsArbitraryBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("ordinary text without executable tokens"))
	if _, ok := decodeRecognizedRecoveredPayload(encoded); ok {
		t.Fatal("arbitrary Base64 accepted as recovered payload")
	}
}

func TestRecoveredArtifactBudgetIsBounded(t *testing.T) {
	pipeline := &Pipeline{}
	analysis := types.NewFileAnalysis("classes.dex", types.FileTypeDex, 1)
	for i := 0; i < maxRecoveredArtifactPayloads+8; i++ {
		analysis.RecoveredStrings = append(analysis.RecoveredStrings, string(rune('a'+i))+".example")
	}
	pipeline.dispatchRecoveredArtifacts(context.Background(), analysis, FileJob{RelPath: "classes.dex", Type: types.FileTypeSmali})
	if analysis.RecoveredArtifactSummary == nil || analysis.RecoveredArtifactSummary.Budgeted == 0 {
		t.Fatalf("payload budget not enforced: %+v", analysis.RecoveredArtifactSummary)
	}
}
