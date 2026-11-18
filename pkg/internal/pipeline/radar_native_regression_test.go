package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
)

func TestNativeProtectionAndLoaderReferencesAreNotPayloadProof(t *testing.T) {
	content := []byte("\x7fELF\x00frida\x00DexClassLoader\x00https://example.com/update\x00")
	ctx := newTestContext("lib/arm64-v8a/libloader.so", content, types.FileTypeNative)
	file := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	detector := NewThreatIndicatorsDetector()
	detector.Detect(ctx, file)
	aggregator := detector.GetAggregator()
	aggregator.RunCorrelations()
	file.Matches = append(file.Matches, aggregator.GenerateMatches()...)
	result := types.NewAnalysisResult("fixture")
	result.Files[ctx.Path] = file
	p := &Pipeline{result: result}
	p.triageFindings()
	p.buildTypedFindings()
	if len(result.Findings) < 3 {
		t.Fatalf("native evidence was removed: %+v", result.Findings)
	}
	for _, item := range result.Findings {
		if item.Kind == finding.KindMalware || item.Kind == finding.KindVulnerability || item.Severity != "info" {
			t.Fatalf("protection/API strings established a payload: %+v", item)
		}
		if item.Explanation == nil || item.Explanation.Status != "observation" || len(item.Evidence) == 0 {
			t.Fatalf("native evidence or limitations lost: %+v", item)
		}
	}
	fs := detector.GetAggregator().GetSignals().Files[ctx.Path]
	if !fs.Has(SignalFrida) || !fs.Has(SignalNativeDexLoader) || !fs.Has(SignalNativeHTTP) {
		t.Fatal("native signals were discarded instead of correcting their interpretation")
	}
	if rating.ComputeResultProfile(result).OverallScore != 0 {
		t.Fatal("native string co-presence increased risk")
	}
	features := projectBehaviorFeatures(aggregator.GetSignals())
	if features[9] != 0 || features[11] != 0 {
		t.Fatal("native string observations became threat correlations in behavioral fusion")
	}
}

func TestNativeProtectionObservationKeepsIndependentEndpointFinding(t *testing.T) {
	content := []byte("\x7fELF\x00frida\x00DexClassLoader\x00discord.com/api/webhooks\x00")
	ctx := newTestContext("lib/arm64-v8a/libunknown.so", content, types.FileTypeNative)
	file := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	NewThreatIndicatorsDetector().Detect(ctx, file)
	result := types.NewAnalysisResult("fixture")
	result.Files[ctx.Path] = file
	(&Pipeline{result: result}).buildTypedFindings()
	for _, item := range result.Findings {
		if item.Kind != finding.KindMalware {
			continue
		}
		for _, evidence := range item.Evidence {
			if strings.Contains(evidence.Snippet, "discord.com/api") {
				return
			}
		}
	}
	t.Fatal("an independent native endpoint finding was suppressed")
}
