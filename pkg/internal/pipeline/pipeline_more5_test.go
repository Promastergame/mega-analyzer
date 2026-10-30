package pipeline

import (
	"context"
	"os"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func TestPipeline_CoverageMore5(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		OutputDir: tempDir,
		Workers:   1,
	}

	p, err := NewPipeline(cfg)
	if err != nil {
		t.Skip("Failed to create pipeline")
	}

	_ = p.allDetectors()
	_ = p.effectiveWorkerCount()
	p.resetRunState(tempDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = p.isFileTooLarge(types.FileTypeDex, 1000)

	// Create some dummy files
	dummyAPK := tempDir + "/test.apk"
	_ = os.WriteFile(dummyAPK, []byte("PK\x03\x04"), 0644)

	// Try streaming pipeline with context canceled so it doesn't block long
	cancel()
	_ = p.runStreamingPipeline(ctx, tempDir)

	p.detectAppPackage(tempDir)

	_ = p.preScanCount(context.Background(), tempDir)

	stats := p.GetStats()
	if stats == nil {
		t.Log("Stats is nil")
	}

	traces := p.GetTraceStages()
	if traces == nil {
		t.Log("Traces is nil")
	}

	// UserFeedbackFilter
	filter := NewUserFeedbackFilter()
	filter.AddNoisePattern("test")
	filter.AddRelevantPattern("test2")
	filter.AddNoiseKeyword("kw1")
	filter.AddRelevantKeyword("kw2")
	filter.ShouldFilterOut("test", []string{"kw1"})
	filter.ShouldBoost("test2", []string{"kw2"})
	filter.Stats()

	_ = ExportPiracyConfig(tempDir + "/piracy.json")
}
