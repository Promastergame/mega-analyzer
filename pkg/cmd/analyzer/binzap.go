package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/binzap"
)

// handleBinzap runs the Go bytecode backend inside the unified analyzer
// process. Unlike the web scanner's active mode, BinZAP "active" analysis is
// offline static taint/dataflow analysis and never contacts or executes a
// target.
func (a *App) handleBinzap(target string) error {
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat BinZAP target: %w", err)
	}

	a.output.Info("══════ BinZAP Bytecode Analysis ══════")
	a.output.Info("Target: %s", target)

	scanTarget := target
	cleanup := ""
	ext := strings.ToLower(filepath.Ext(target))
	if !info.IsDir() && ext != ".apk" && ext != ".smali" && ext != ".asm" && ext != ".s" {
		return fmt.Errorf("unsupported bytecode target %q: use APK, Smali, ASM, or a directory; use --scan-native for PE/ELF/.so", target)
	}
	if !info.IsDir() && ext == ".apk" {
		scanTarget, err = binzap.UnpackAPK(context.Background(), target)
		if err != nil {
			return fmt.Errorf("unpack APK for BinZAP: %w", err)
		}
		cleanup = scanTarget
		if !a.opts.KeepTemp {
			defer os.RemoveAll(cleanup)
		}
	}

	var findings []binzap.Finding
	if scanInfo, statErr := os.Stat(scanTarget); statErr != nil {
		return fmt.Errorf("stat prepared BinZAP target: %w", statErr)
	} else if scanInfo.IsDir() {
		findings, err = binzap.RunScanDirectory(context.Background(), scanTarget, binzap.ScanOptions{
			Workers: a.opts.Workers,
			Active:  a.opts.BinzapActive,
		})
	} else {
		findings, err = binzap.RunPassiveFile(scanTarget)
		if err == nil && a.opts.BinzapActive {
			var active []binzap.Finding
			active, err = binzap.RunActiveFile(scanTarget)
			findings = append(findings, active...)
		}
		findings = binzap.SortFindings(binzap.DedupeFindings(findings))
	}
	if err != nil {
		return fmt.Errorf("BinZAP scan: %w", err)
	}

	outputDir := a.opts.Output
	if outputDir == "" {
		outputDir = "analysis_output"
	}
	outputDir = filepath.Join(outputDir, "bytecode")
	baseName := strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
	if baseName == "" || baseName == "." {
		baseName = "target"
	}
	if err := binzap.GenerateFullReport(findings, outputDir, baseName); err != nil {
		return fmt.Errorf("write BinZAP report: %w", err)
	}

	a.output.Success("BinZAP complete. Detected %d finding(s).", len(findings))
	a.output.Info("Reports: %s", outputDir)
	if cleanup != "" && a.opts.KeepTemp {
		a.output.Info("Prepared APK kept at: %s", cleanup)
	}
	return nil
}
