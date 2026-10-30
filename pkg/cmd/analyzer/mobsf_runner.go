package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"mega-analyzer/pkg/internal/apkid"
	"mega-analyzer/pkg/internal/manifestaudit"
	"mega-analyzer/pkg/internal/nsc"
	"mega-analyzer/pkg/internal/sastrules"
	"mega-analyzer/pkg/internal/scanbus"
	"mega-analyzer/pkg/internal/trackers"
	"mega-analyzer/pkg/internal/types"
)

// runMobSFModules runs the five MobSF-derived sidecar analyzers
// when their corresponding CLI flags are enabled. Each module
// writes its own JSON + Markdown report under analysis_output/mobsf/
// and contributes high-level findings back into the global result.
func (a *App) runMobSFModules(result *types.AnalysisResult, target, outputDir string) {
	if a == nil || a.opts == nil || result == nil {
		return
	}
	if !(a.opts.EnableSASTRules || a.opts.EnableTrackers || a.opts.EnableNSCAudit ||
		a.opts.EnableManifestAudit || a.opts.EnableAPKID) {
		return
	}
	dir := filepath.Join(outputDir, "mobsf")
	cache := newMobSFCache(outputDir, a.originalAPKPath, target)
	a.output.Info("Running MobSF-derived modules...")

	type moduleTask struct {
		enabled bool
		run     func(*types.AnalysisResult)
	}
	var sastFiles, trackerFiles chan scanbus.File
	sharedFiles := a.opts.EnableSASTRules && a.opts.EnableTrackers &&
		!(cache.has("sast_rules") && cache.has("trackers"))
	if sharedFiles {
		sastFiles = make(chan scanbus.File, 4)
		trackerFiles = make(chan scanbus.File, 4)
	}
	tasks := []moduleTask{
		{a.opts.EnableSASTRules, func(local *types.AnalysisResult) { a.runSASTRules(local, target, dir, sastFiles, cache) }},
		{a.opts.EnableTrackers, func(local *types.AnalysisResult) { a.runTrackers(local, target, dir, trackerFiles, cache) }},
		{a.opts.EnableManifestAudit, func(local *types.AnalysisResult) { a.runManifestAudit(local, target, dir, cache) }},
		{a.opts.EnableNSCAudit, func(local *types.AnalysisResult) { a.runNSCAudit(local, target, dir, cache) }},
		{a.opts.EnableAPKID, func(local *types.AnalysisResult) { a.runAPKID(local, target, dir, cache) }},
	}

	// Three concurrent modules keep SSDs busy without multiplying every
	// module's own worker pool into scheduler and page-cache thrashing.
	parallel := runtime.GOMAXPROCS(0)
	if parallel > 3 {
		parallel = 3
	}
	if parallel < 1 {
		parallel = 1
	}
	sem := make(chan struct{}, parallel)
	locals := make([]*types.AnalysisResult, len(tasks))
	var wg sync.WaitGroup
	for i, task := range tasks {
		if !task.enabled {
			continue
		}
		locals[i] = moduleResultView(result)
		wg.Add(1)
		go func(i int, task moduleTask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			task.run(locals[i])
		}(i, task)
	}
	var busErr <-chan error
	if sharedFiles {
		ch := make(chan error, 1)
		busErr = ch
		go func() {
			ch <- scanbus.Stream(context.Background(), target, sastFiles, trackerFiles)
			close(ch)
		}()
	}
	wg.Wait()
	if busErr != nil {
		if err := <-busErr; err != nil {
			a.output.Warning("shared MobSF file stream failed: %v", err)
		}
	}
	// Merge in task order so JSON/report ordering remains deterministic.
	for _, local := range locals {
		if local != nil {
			result.ArtifactFindings = append(result.ArtifactFindings, local.ArtifactFindings...)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual runners
// ─────────────────────────────────────────────────────────────────────────────

func (a *App) runSASTRules(result *types.AnalysisResult, target, dir string, files <-chan scanbus.File, cache *mobSFCache) {
	eng, err := sastrules.NewEngineFromEmbedded()
	if err != nil {
		if files != nil {
			for range files {
			}
		}
		a.output.Warning("SAST rules: %v", err)
		return
	}
	var rep *sastrules.Report
	var cached sastrules.Report
	if cache.load("sast_rules", &cached) {
		rep = &cached
		rep.Target = target
		if files != nil {
			for range files {
			}
		}
		a.output.Info("SAST rules: cache hit")
	} else {
		if files == nil {
			rep, err = eng.Scan(target)
		} else {
			rep, err = eng.ScanFiles(target, files)
		}
	}
	if err != nil {
		a.output.Warning("SAST rules scan failed: %v", err)
		return
	}
	if err := cache.save("sast_rules", rep); err != nil {
		a.output.Warning("SAST cache write: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "sast_rules.json"), rep); err != nil {
		a.output.Warning("write sast_rules.json: %v", err)
	}
	if err := writeText(filepath.Join(dir, "SAST_RULES.md"), sastrules.RenderMarkdown(rep)); err != nil {
		a.output.Warning("write SAST_RULES.md: %v", err)
	}
	a.output.Success("SAST rules: %d findings (score %d/%s)", len(rep.Matches), rep.Score, rep.Verdict)

	for _, fe := range sastrules.SummarizeFindings(rep) {
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     fe.Path,
			Severity: mapSastSeverity(fe.Severity),
			Reason:   fe.Reason,
			Stages:   []string{"module: sast_rules", "sidecar: mobsf/SAST_RULES.md"},
		})
	}
}

func (a *App) runTrackers(result *types.AnalysisResult, target, dir string, files <-chan scanbus.File, cache *mobSFCache) {
	var rep *trackers.Report
	var err error
	var cached trackers.Report
	if cache.load("trackers", &cached) {
		rep = &cached
		rep.Target = target
		if files != nil {
			for range files {
			}
		}
		a.output.Info("Trackers: cache hit")
	} else {
		if files == nil {
			rep, err = trackers.Scan(target)
		} else {
			rep, err = trackers.ScanFiles(target, files)
		}
	}
	if err != nil {
		a.output.Warning("Trackers scan failed: %v", err)
		return
	}
	if err := cache.save("trackers", rep); err != nil {
		a.output.Warning("Trackers cache write: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "trackers.json"), rep); err != nil {
		a.output.Warning("write trackers.json: %v", err)
	}
	if err := writeText(filepath.Join(dir, "TRACKERS.md"), trackers.RenderMarkdown(rep)); err != nil {
		a.output.Warning("write TRACKERS.md: %v", err)
	}
	a.output.Success("Trackers: %d detected (verdict: %s)", rep.Total, rep.Verdict)

	if rep.Total > 0 {
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     "mobsf/TRACKERS.md",
			Severity: trackerVerdictSeverity(rep),
			Reason:   fmt.Sprintf("Detected %d trackers — verdict: %s", rep.Total, rep.Verdict),
			Stages:   []string{"module: trackers", "sidecar: mobsf/TRACKERS.md"},
		})
	}
}

func (a *App) runManifestAudit(result *types.AnalysisResult, target, dir string, cache *mobSFCache) {
	var rep *manifestaudit.Report
	var cached manifestaudit.Report
	if cache.load("manifest_audit", &cached) {
		rep = &cached
		a.output.Info("Manifest audit: cache hit")
	} else {
		manifest, err := manifestaudit.LoadManifest(target)
		if err != nil {
			a.output.Warning("Manifest audit: load: %v", err)
			return
		}
		rep = manifestaudit.Audit(target, manifest)
	}
	if err := cache.save("manifest_audit", rep); err != nil {
		a.output.Warning("Manifest cache write: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "manifest_audit.json"), rep); err != nil {
		a.output.Warning("write manifest_audit.json: %v", err)
	}
	if err := writeText(filepath.Join(dir, "MANIFEST_AUDIT.md"), manifestaudit.RenderMarkdown(rep)); err != nil {
		a.output.Warning("write MANIFEST_AUDIT.md: %v", err)
	}
	a.output.Success("Manifest audit: %d issues (score %d/%s)", len(rep.Issues), rep.Score, rep.Verdict)

	for _, is := range rep.Issues {
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     "mobsf/MANIFEST_AUDIT.md",
			Severity: mapManifestSeverity(is.Severity),
			Reason:   fmt.Sprintf("[%s] %s", is.ID, is.Title),
			Stages:   []string{"module: manifest_audit", "sidecar: mobsf/MANIFEST_AUDIT.md"},
		})
	}
}

func (a *App) runNSCAudit(result *types.AnalysisResult, target, dir string, cache *mobSFCache) {
	var rep *nsc.Report
	var cached nsc.Report
	if cache.load("nsc_audit", &cached) {
		rep = &cached
		a.output.Info("NSC audit: cache hit")
	} else {
		var err error
		rep, err = nsc.AuditDir(target)
		if err != nil {
			a.output.Warning("NSC audit failed: %v", err)
			return
		}
	}
	if err := cache.save("nsc_audit", rep); err != nil {
		a.output.Warning("NSC cache write: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "nsc_audit.json"), rep); err != nil {
		a.output.Warning("write nsc_audit.json: %v", err)
	}
	if err := writeText(filepath.Join(dir, "NSC_AUDIT.md"), nsc.RenderMarkdown(rep)); err != nil {
		a.output.Warning("write NSC_AUDIT.md: %v", err)
	}
	a.output.Success("NSC audit: %d findings (score %d/%s)", len(rep.Issues), rep.Score, rep.Verdict)

	for _, is := range rep.Issues {
		if is.Severity == nsc.SevSecure {
			continue
		}
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     "mobsf/NSC_AUDIT.md",
			Severity: mapNSCSeverity(is.Severity),
			Reason:   fmt.Sprintf("[%s] %s", is.ID, is.Title),
			Stages:   []string{"module: nsc_audit", "sidecar: mobsf/NSC_AUDIT.md"},
		})
	}
}

func (a *App) runAPKID(result *types.AnalysisResult, target, dir string, cache *mobSFCache) {
	var rep *apkid.Report
	var cached apkid.Report
	if cache.load("apkid", &cached) {
		rep = &cached
		rep.Target = target
		a.output.Info("APKiD: cache hit")
	} else {
		var err error
		rep, err = apkid.Scan(target)
		if err != nil {
			a.output.Warning("APKiD scan failed: %v", err)
			return
		}
	}
	if err := cache.save("apkid", rep); err != nil {
		a.output.Warning("APKiD cache write: %v", err)
	}
	if err := writeJSON(filepath.Join(dir, "apkid.json"), rep); err != nil {
		a.output.Warning("write apkid.json: %v", err)
	}
	a.output.Success("APKiD: %s (score %d, %d signature hits)", rep.Summary, rep.Score, len(rep.Matches))

	if rep.Score > 0 || len(rep.Matches) > 0 {
		sev := types.SeverityInfo
		switch {
		case rep.Score >= 30:
			sev = types.SeverityHigh
		case rep.Score >= 15:
			sev = types.SeverityMedium
		case rep.Score > 0:
			sev = types.SeverityLow
		}
		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     "mobsf/apkid.json",
			Severity: sev,
			Reason:   fmt.Sprintf("APKiD: %s", rep.Summary),
			Stages:   []string{"module: apkid", "sidecar: mobsf/apkid.json"},
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeText(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func mapSastSeverity(s sastrules.Severity) types.Severity {
	switch s {
	case sastrules.SevCritical:
		return types.SeverityCritical
	case sastrules.SevHigh:
		return types.SeverityHigh
	case sastrules.SevMedium:
		return types.SeverityMedium
	case sastrules.SevLow:
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func mapManifestSeverity(s manifestaudit.Severity) types.Severity {
	switch s {
	case manifestaudit.SevCritical:
		return types.SeverityCritical
	case manifestaudit.SevHigh:
		return types.SeverityHigh
	case manifestaudit.SevMedium:
		return types.SeverityMedium
	case manifestaudit.SevLow:
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func mapNSCSeverity(s nsc.Severity) types.Severity {
	switch s {
	case nsc.SevCritical:
		return types.SeverityCritical
	case nsc.SevHigh:
		return types.SeverityHigh
	case nsc.SevMedium:
		return types.SeverityMedium
	case nsc.SevLow:
		return types.SeverityLow
	}
	return types.SeverityInfo
}

func trackerVerdictSeverity(r *trackers.Report) types.Severity {
	switch r.Verdict {
	case "extreme":
		return types.SeverityHigh
	case "heavy":
		return types.SeverityMedium
	case "moderate":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
