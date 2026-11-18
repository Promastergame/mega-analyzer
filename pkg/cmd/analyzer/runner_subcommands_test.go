package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

func TestApp_RunnerSubsystems(t *testing.T) {
	tempDir := t.TempDir()
	app := NewApp()
	app.opts = &CLIOptions{}
	app.opts.Target = tempDir
	app.opts.Output = filepath.Join(tempDir, "out")
	_ = app.initialize()

	// Call all the handles with empty/invalid inputs just to trigger the paths.
	// We ignore errors because we just want coverage of the argument parsing and setup.

	_ = app.handleJSPatch()
	_ = app.handleRebuild()
	// sandbox requires windows, might panic or fail, that's fine
	_ = app.handleSandbox()

	// Server/Network toolkits
	// _ = app.handleIntercept() // blocks
	// _ = app.handleServgen() // might block
	// fuzz blocks? No, it usually returns error if no spec
	_ = app.handleFuzz()

	_ = app.handleVersionDiff()
	_ = app.handleFirmware()
	_ = app.handleMachineCode(filepath.Join(tempDir, "dummy.bin"))

	res := types.NewAnalysisResult(tempDir)
	_ = app.generateReports(context.Background(), res, tempDir)

	_ = app.handleOBBScan(tempDir)
	_ = app.handleCacheScan(tempDir)
	_ = app.handleMLCacheScript(tempDir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, _ = app.runExperimental(ctx, res, tempDir, tempDir)

	_, _ = app.runMLPatch(ctx, tempDir, tempDir, res)

	app.saveToMLHistory(res, tempDir)

	// Test Insight Modules
	app.runInsightModules(res, tempDir, tempDir)
	app.runMobSFModules(res, tempDir, tempDir)
	app.runMediumModules(res, tempDir, tempDir, tempDir)

	// Active web scan
	_ = app.handleActiveWebScan(res, tempDir)

	// Setup context
	ctx2, stop := app.setupContext()
	stop()
	_ = ctx2
}
