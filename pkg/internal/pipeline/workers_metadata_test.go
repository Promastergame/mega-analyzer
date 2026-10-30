// workers_metadata_test.go — finding metadata enrichment (audit P2-13 / E1).
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

const metadataFixture = `
.class public Lcom/app/Meta;
.method public risky()V
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    return-void
.end method
`

func TestEnrichMetadata_FillsMethodClassConfidence(t *testing.T) {
	class := parseCryptoFixture(t, metadataFixture)
	content := []byte(metadataFixture)
	ctx := createDetectorCtx("smali/com/app/Meta.smali", content, types.FileTypeSmali)
	ctx.Class = class

	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	// A byte-pattern finding inside the method body (line 4 of the fixture:
	// the invoke sits between LineStart and LineEnd).
	line := class.Methods[0].LineStart + 2
	analysis.Matches = append(analysis.Matches, newMatch(types.CategoryMalware, ctx.Path, line, "pattern hit", "getRuntime", false))

	enrichSmaliMatchMetadata(ctx, analysis, 0)

	m := analysis.Matches[0]
	if m.MethodName != "risky" {
		t.Errorf("MethodName = %q, want risky", m.MethodName)
	}
	if m.ClassName != "com.app.Meta" {
		t.Errorf("ClassName = %q, want com.app.Meta", m.ClassName)
	}
	if m.Confidence != "low" {
		t.Errorf("plain pattern evidence → Confidence=low, got %q", m.Confidence)
	}
}

func TestEnrichMetadata_CriticalDefaultsMedium(t *testing.T) {
	class := parseCryptoFixture(t, metadataFixture)
	ctx := createDetectorCtx("smali/com/app/Meta.smali", []byte(metadataFixture), types.FileTypeSmali)
	ctx.Class = class

	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(metadataFixture)))
	analysis.Matches = append(analysis.Matches, newMatch(types.CategoryMalware, ctx.Path, class.Methods[0].LineStart, "critical hit", "x", true))

	enrichSmaliMatchMetadata(ctx, analysis, 0)
	if analysis.Matches[0].Confidence != "medium" {
		t.Errorf("critical pattern evidence → Confidence=medium, got %q", analysis.Matches[0].Confidence)
	}
}

func TestEnrichMetadata_PreservesDetectorProvidedValues(t *testing.T) {
	class := parseCryptoFixture(t, metadataFixture)
	ctx := createDetectorCtx("smali/com/app/Meta.smali", []byte(metadataFixture), types.FileTypeSmali)
	ctx.Class = class

	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(metadataFixture)))
	match := newMatch(types.CategoryWeakCrypto, ctx.Path, class.Methods[0].LineStart, "ast hit", "x", true)
	match.MethodName = "custom"
	match.ClassName = "custom.Class"
	match.Confidence = "high"
	analysis.Matches = append(analysis.Matches, match)

	enrichSmaliMatchMetadata(ctx, analysis, 0)

	m := analysis.Matches[0]
	if m.MethodName != "custom" || m.ClassName != "custom.Class" || m.Confidence != "high" {
		t.Errorf("detector-provided metadata must not be overwritten: %+v", m)
	}
}

func TestEnrichMetadata_NonSmaliUntouched(t *testing.T) {
	ctx := createDetectorCtx("AndroidManifest.xml", []byte("<manifest/>"), types.FileTypeXML)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, 11)
	analysis.Matches = append(analysis.Matches, newMatch(types.CategoryExportedComponent, ctx.Path, 1, "exported", "x", false))

	enrichSmaliMatchMetadata(ctx, analysis, 0)
	if analysis.Matches[0].Confidence != "" {
		t.Errorf("non-smali files must not be enriched, Confidence=%q", analysis.Matches[0].Confidence)
	}
}
