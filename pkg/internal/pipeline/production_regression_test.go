package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/finding"
)

func leanPipelineConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Workers = 1
	cfg.EnableCallGraph = false
	cfg.EnableDeobfuscation = false
	cfg.EnableCrackPointAnalysis = false
	cfg.EnableAnomalyDetection = false
	cfg.EnableContentCache = false
	return cfg
}

func TestPipelineCoverageIncludesFileWithoutFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "plain.txt"), []byte("ordinary neutral sentence"), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(leanPipelineConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if result.Coverage.Parsed != 1 || result.Stats.AnalyzedFiles != 1 {
		t.Fatalf("physical coverage lost no-finding file: coverage=%+v stats=%+v", result.Coverage, result.Stats)
	}
	if len(result.Files) != 0 {
		t.Fatalf("no-finding file should not be retained in result payload: %v", result.Files)
	}
}

func TestPipelineCoverageReportsMaxFilesLimit(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("ordinary neutral sentence"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := leanPipelineConfig(t)
	cfg.MaxFiles = 1
	p, err := NewPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Run(context.Background(), root)
	if err != nil {
		t.Fatalf("configured MaxFiles must not be a scan error: %v", err)
	}
	if !result.Coverage.LimitReached || result.Coverage.Queued != 1 || result.Coverage.SkippedByLimit != 1 {
		t.Fatalf("unexpected limit coverage: %+v", result.Coverage)
	}
}

func TestPipelineDataFlowProducesTypedFinding(t *testing.T) {
	root := t.TempDir()
	smaliDir := filepath.Join(root, "smali", "com", "example")
	if err := os.MkdirAll(smaliDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "AndroidManifest.xml"), []byte(`<manifest package="com.example"><application /></manifest>`), 0644); err != nil {
		t.Fatal(err)
	}
	smali := `.class public Lcom/example/Flow;
.super Ljava/lang/Object;
.method public static run(Landroid/content/Intent;Ljava/lang/String;)V
    .locals 2
    invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method
`
	if err := os.WriteFile(filepath.Join(smaliDir, "Flow.smali"), []byte(smali), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(leanPipelineConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.DataFlows) == 0 || result.DataFlows[0].Category != "command_injection" {
		t.Fatalf("missing end-to-end data-flow finding: flows=%+v stats=%+v", result.DataFlows, result.DataFlowStats)
	}
	foundTyped := false
	for _, item := range result.Findings {
		if item.RuleID == "dataflow.command_injection" && item.Kind == finding.KindVulnerability && len(item.Evidence) > 0 {
			foundTyped = true
		}
	}
	if !foundTyped {
		t.Fatalf("data-flow was not included in typed findings: %+v", result.Findings)
	}
}
