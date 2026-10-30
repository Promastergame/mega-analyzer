package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/apkloader/obb"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OBB / DATA / CACHE SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) handleOBBScan(outputDir string) error {
	// Determine scan target
	scanDir := a.opts.OBBDataDir
	if scanDir == "" && a.extractor != nil && a.extractor.Meta != nil {
		// Auto-detect from package name: Android/obb/<package> or Android/data/<package>
		pkg := a.extractor.Meta.Package
		if pkg != "" {
			candidates := []string{
				filepath.Join(os.Getenv("ANDROID_OBB"), pkg),
				filepath.Join(os.Getenv("ANDROID_DATA"), pkg),
				"Android/obb/" + pkg,
				"Android/data/" + pkg,
			}
			for _, c := range candidates {
				if info, err := os.Stat(c); err == nil && info.IsDir() {
					scanDir = c
					break
				}
			}
		}
	}
	if scanDir == "" {
		// Fall back to looking for .obb in the target directory
		if a.opts.Target != "" {
			scanDir = a.opts.Target
		} else {
			return fmt.Errorf("no OBB/data directory specified and auto-detect failed")
		}
	}

	absDir, err := filepath.Abs(scanDir)
	if err != nil {
		return fmt.Errorf("invalid OBB directory: %w", err)
	}

	a.output.Info("[OBB Scanner] Scanning: %s", absDir)

	cfg := obb.DefaultAnalyzerConfig()
	if a.opts.OBBMaxSizeMB > 0 {
		cfg.MaxFileSizeMB = a.opts.OBBMaxSizeMB
	}
	cfg.OutputDir = outputDir
	cfg.ExtractFindings = a.opts.OBBOutputJSON

	results, err := obb.AnalyzeDirectory(context.Background(), absDir, cfg)
	if err != nil {
		return fmt.Errorf("OBB analysis failed: %w", err)
	}

	if len(results) == 0 {
		a.output.Info("[OBB Scanner] No OBB/data/cache files found.")
		return nil
	}

	var totalBundles, totalPayloads, totalURLs, totalTrackers int
	for _, r := range results {
		totalBundles += len(r.AssetBundles)
		totalPayloads += len(r.HiddenPayloads)
		totalURLs += len(r.SuspiciousURLs)
		totalTrackers += len(r.TrackerHints)
	}

	a.output.Success("[OBB Scanner] Scanned %d archives: %d bundles, %d payloads, %d URLs, %d trackers",
		len(results), totalBundles, totalPayloads, totalURLs, totalTrackers)

	for _, r := range results {
		for _, p := range r.HiddenPayloads {
			sev := "⚠ "
			if p.Severity == "high" {
				sev = "🚨 "
			}
			a.output.Warning("%sOBB hidden payload: %s (%s) — %s", sev, p.Type, p.Path, p.Description)
		}
		for _, u := range r.SuspiciousURLs {
			a.output.Info("  OBB URL: %s", u)
		}
	}

	if a.opts.OBBOutputJSON {
		a.output.Info("  Report written to: %s", filepath.Join(outputDir, "OBB_SCAN_REPORT.json"))
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE SECURITY ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) handleCacheScan(outputDir string) error {
	cacheDir := a.opts.CacheDataDir
	pkg := ""

	if a.extractor != nil && a.extractor.Meta != nil {
		pkg = a.extractor.Meta.Package
	}

	if cacheDir == "" && pkg != "" {
		candidates := []string{
			filepath.Join(os.Getenv("ANDROID_DATA"), pkg, "cache"),
			filepath.Join(os.Getenv("EXTERNAL_STORAGE"), "Android", "data", pkg, "cache"),
			filepath.Join("Android", "data", pkg, "cache"),
		}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && info.IsDir() {
				cacheDir = c
				break
			}
		}
	}

	if cacheDir == "" {
		return fmt.Errorf("no cache directory found (use --cache-data-dir)")
	}

	absDir, err := filepath.Abs(cacheDir)
	if err != nil {
		return fmt.Errorf("invalid cache dir: %w", err)
	}

	a.output.Info("[Cache Analyzer] Scanning: %s", absDir)

	ca := apkloader.NewCacheAnalyzer(pkg, absDir)
	if err := ca.Scan(); err != nil {
		return err
	}

	if len(ca.Findings) == 0 {
		a.output.Success("[Cache Analyzer] No security issues found in cache.")
		return nil
	}

	var critical, high, medium int
	for _, f := range ca.Findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
	}

	a.output.Success("[Cache Analyzer] %d findings: %d critical, %d high, %d medium",
		len(ca.Findings), critical, high, medium)

	for _, f := range ca.Findings {
		sev := "⚠ "
		switch f.Severity {
		case "critical":
			sev = "🚨 "
		case "high":
			sev = "🔴 "
		}
		a.output.Warning("%s[%s] %s: %s", sev, f.Type, f.Path, f.Description)
		if f.Snippet != "" {
			a.output.Info("   snippet: %s", f.Snippet)
		}
	}

	if err := ca.WriteReport(outputDir); err != nil {
		a.output.Warning("Failed to write cache report: %v", err)
	} else {
		a.output.Info("  Report written to: %s", filepath.Join(outputDir, "CACHE_ANALYSIS.json"))
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-APLI-CACHE SCRIPT
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) handleMLCacheScript(outputDir string) error {
	cacheDir := a.opts.CacheDataDir
	pkg := ""
	if a.extractor != nil && a.extractor.Meta != nil {
		pkg = a.extractor.Meta.Package
	}

	if cacheDir == "" && pkg != "" {
		candidates := []string{
			filepath.Join(os.Getenv("ANDROID_DATA"), pkg, "cache"),
			filepath.Join(os.Getenv("EXTERNAL_STORAGE"), "Android", "data", pkg, "cache"),
			filepath.Join("Android", "data", pkg, "cache"),
		}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && info.IsDir() {
				cacheDir = c
				break
			}
		}
	}
	if cacheDir == "" {
		return fmt.Errorf("no cache directory found (use --cache-data-dir)")
	}

	absDir, err := filepath.Abs(cacheDir)
	if err != nil {
		return fmt.Errorf("invalid cache dir: %w", err)
	}

	a.output.Info("[ML-Apli-Cache] Running predictive exploitation analysis on: %s", absDir)

	res, err := apkloader.RunMLCacheScript(pkg, absDir, outputDir)
	if err != nil {
		return err
	}

	a.output.Success("[ML-Apli-Cache] Analysis complete — Risk Score: %.0f%% (%d findings)",
		res.RiskScore*100, res.TotalFindings)

	if len(res.ExploitChain) > 0 {
		a.output.Warning("[ML-Apli-Cache] Predicted Attack Chain (%d steps):", len(res.ExploitChain))
		for _, step := range res.ExploitChain {
			a.output.Warning("  %d. %s → %s", step.Step, step.Title, step.FindingRef)
			a.output.Info("     %s", step.Description)
		}
	}

	if len(res.Remediation) > 0 {
		a.output.Info("[ML-Apli-Cache] Top Remediation Actions:")
		for _, r := range res.Remediation {
			icon := "🔧"
			if r.Priority == 1 {
				icon = "🚨"
			}
			a.output.Info("  %s P%d: %s [%s, ~%s]", icon, r.Priority, r.Action, r.Difficulty, r.EstTime)
		}
	}

	a.output.Info("[ML-Apli-Cache] Conclusion: %s", res.Conclusion)
	a.output.Info("  Report written to: %s", filepath.Join(outputDir, "ML_APLI_CACHE_REPORT.json"))

	return nil
}
