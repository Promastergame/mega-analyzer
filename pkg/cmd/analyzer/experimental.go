package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/experimental"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXPERIMENTAL SUBSYSTEM RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

// listExperimentalModules prints available experimental modules and presets.
func (a *App) listExperimentalModules() error {
	reg := experimental.DefaultRegistry()
	fmt.Println("Experimental modules (--ml-ex-apply <selector>):")
	fmt.Println()
	for i, m := range reg.All() {
		aliases := ""
		if al := m.Aliases(); len(al) > 0 {
			aliases = " (aliases: " + strings.Join(al, ", ") + ")"
		}
		fmt.Printf("  %d) %-7s — %s%s\n", i+1, m.ID(), m.Description(), aliases)
		fmt.Printf("     tier: %s\n", m.Tier())
	}
	fmt.Println()
	fmt.Println("Presets:")
	for name, ids := range experimental.Presets {
		fmt.Printf("  %-8s -> %s\n", name, strings.Join(ids, ", "))
	}
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  --ml-ex-apply 1-4")
	fmt.Println("  --ml-ex-apply macho,binsim")
	fmt.Println("  --ml-ex-apply alice")
	fmt.Println("  --aeg                       (shortcut for --ml-ex-apply aeg)")
	return nil
}

// runExperimental orchestrates the experimental subsystem against a target.
//
// It is a no-op (returns nil) when --ml-ex / --aeg / --ml-ex-apply were not
// supplied. The runner is invoked AFTER the main analysis has produced
// reports, so its findings can extend ArtifactFindings without colliding
// with pipeline state.
func (a *App) runExperimental(ctx context.Context, result *types.AnalysisResult, targetDir, outputDir string) (*experimental.Result, error) {
	if a.opts == nil || !a.opts.MLEx {
		return nil, nil
	}

	reg := experimental.DefaultRegistry()
	selected, err := experimental.ParseSelector(a.opts.MLExApply, reg)
	if err != nil {
		return nil, fmt.Errorf("invalid --ml-ex-apply selector: %w", err)
	}
	if len(selected) == 0 {
		// Defensive: should never happen because Validate() defaults to "all".
		return nil, nil
	}

	exOutDir := a.opts.MLExOutput
	if exOutDir == "" {
		exOutDir = filepath.Join(outputDir, "experimental")
	}
	if err := os.MkdirAll(exOutDir, 0o755); err != nil {
		return nil, fmt.Errorf("create experimental output dir: %w", err)
	}

	pkgName := ""
	if result != nil {
		pkgName = result.AppPackage
	}

	in := experimental.Input{
		TargetDir:   targetDir,
		OriginalAPK: a.opts.Target,
		OutputDir:   exOutDir,
		Profile:     string(a.opts.Profile),
		Metadata: map[string]string{
			"package": pkgName,
		},
	}

	timeout := time.Duration(a.opts.MLExTimeout) * time.Second

	a.output.Println()
	a.output.Info("Running experimental modules: %s", joinModuleIDs(selected))

	opts := experimental.Options{
		Selected:         selected,
		PerModuleTimeout: timeout,
		Parallel:         a.opts.MLExParallel,
		OnStart: func(m experimental.Module) {
			a.output.Info("  ▶ %s — %s", m.ID(), m.Name())
		},
		OnFinish: func(m experimental.Module, res *experimental.ModuleResult, err error) {
			if err != nil {
				a.output.Warning("  ✗ %s failed: %v", m.ID(), err)
				return
			}
			if res.Skipped {
				a.output.Warning("  ⤼ %s skipped: %s", m.ID(), res.SkipReason)
				return
			}
			a.output.Success("  ✓ %s done in %s — %d findings",
				m.ID(), res.Duration.Round(time.Millisecond), len(res.Findings))
		},
	}

	exResult, err := experimental.Run(ctx, in, opts)
	if err != nil {
		return nil, err
	}

	// Persist JSON sidecar if requested.
	if a.opts.MLExJSON {
		if err := writeExperimentalJSON(exResult, exOutDir); err != nil {
			a.output.Warning("Failed to write experimental_report.json: %v", err)
		}
	}

	// Inject experimental findings into the static result so they appear in
	// HTML / markdown reports as ArtifactFindings.
	if result != nil {
		injectExperimentalFindings(result, exResult, targetDir)
	}

	a.output.Println()
	a.output.Info("Experimental subsystem complete: %d findings, highest=%s",
		exResult.TotalFindings(), exResult.HighestSeverity())

	return exResult, nil
}

func joinModuleIDs(modules []experimental.Module) string {
	ids := make([]string, len(modules))
	for i, m := range modules {
		ids[i] = m.ID()
	}
	return strings.Join(ids, ", ")
}

// writeExperimentalJSON persists the run result.
func writeExperimentalJSON(res *experimental.Result, dir string) error {
	if res == nil {
		return nil
	}
	path := filepath.Join(dir, "experimental_report.json")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// injectExperimentalFindings maps experimental findings into ArtifactFindings.
func injectExperimentalFindings(result *types.AnalysisResult, ex *experimental.Result, targetDir string) {
	if ex == nil || result == nil {
		return
	}
	for _, mod := range ex.Modules {
		if mod == nil {
			continue
		}
		for _, f := range mod.Findings {
			rel := f.File
			if rel != "" && targetDir != "" {
				if r, err := filepath.Rel(targetDir, f.File); err == nil && r != "" {
					rel = r
				}
			}
			result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
				Path:     rel,
				Severity: experimentalSeverityToTypes(f.Severity),
				Reason:   fmt.Sprintf("[%s] %s", mod.ModuleID, f.Title),
				Payload:  f.Description,
				Stages:   append([]string{"experimental:" + mod.ModuleID}, f.Tags...),
			})
		}
	}
}

func experimentalSeverityToTypes(s experimental.Severity) types.Severity {
	switch s {
	case experimental.SevCritical:
		return types.SeverityCritical
	case experimental.SevHigh:
		return types.SeverityHigh
	case experimental.SevMedium:
		return types.SeverityMedium
	case experimental.SevLow:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
