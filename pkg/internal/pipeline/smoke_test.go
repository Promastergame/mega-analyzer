package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/config"
)

func TestSmokePipeline(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Workers = 1
	cfg.EnableCallGraph = false
	cfg.EnableCorrelations = false
	cfg.EnableEntropyAnalysis = false

	p, err := NewPipeline(cfg)
	if err != nil {
		t.Fatalf("NewPipeline failed: %v", err)
	}

	dir := t.TempDir()
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.test"></manifest>`
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	smaliDir := filepath.Join(dir, "smali")
	if err := os.MkdirAll(smaliDir, 0755); err != nil {
		t.Fatalf("mkdir smali: %v", err)
	}

	smali := `.class public Lcom/example/Test;
.super Ljava/lang/Object;

.method public isPremium()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
`
	if err := os.WriteFile(filepath.Join(smaliDir, "Test.smali"), []byte(smali), 0644); err != nil {
		t.Fatalf("write smali: %v", err)
	}

	if _, err := p.Run(context.Background(), dir); err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}
}
