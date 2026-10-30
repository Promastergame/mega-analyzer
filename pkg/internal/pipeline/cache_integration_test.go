package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/config"
)

func TestPipelineContentCacheHitsOnSecondRun(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	smaliDir := filepath.Join(root, "smali", "com", "example")
	if err := os.MkdirAll(smaliDir, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `<manifest package="com.example"><application /></manifest>`
	if err := os.WriteFile(filepath.Join(root, "AndroidManifest.xml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	smali := `.class public Lcom/example/Checker;
.super Ljava/lang/Object;

.method public isLicenseValid()Z
    .locals 1
    const/4 v0, 0x1
    if-eqz v0, :invalid
    return v0
    :invalid
    const/4 v0, 0x0
    return v0
.end method
`
	if err := os.WriteFile(filepath.Join(smaliDir, "Checker.smali"), []byte(smali), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Workers = 1
	cfg.EnableContentCache = true // the cache is opt-in; the dir alone is not enough
	cfg.ContentCacheDir = cacheDir
	p, err := NewPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Cache.MethodStores == 0 {
		t.Fatalf("first run did not populate method cache: %+v", first.Cache)
	}
	second, err := p.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if second.Cache.MethodHits == 0 {
		t.Fatalf("second run did not reuse method cache: %+v", second.Cache)
	}
}
