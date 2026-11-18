package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mega-analyzer/pkg/internal/types"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/decompiler"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/jspatcher"
)

func isStandaloneBundle(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bundle", ".hbc", ".jsbundle", ".js", ".mjs", ".cjs":
		return true
	}
	// Bytecode can also be shipped with no extension.
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	header := make([]byte, 8)
	n, _ := f.Read(header)
	return apkloader.IsHermesBytecode(header[:n])
}

func (a *App) prepareBundle(ctx context.Context, input string) (string, error) {
	started := time.Now()
	data, err := apkloader.ReadBundleFile(ctx, input)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "analyzer_bundle_*")
	if err != nil {
		return "", err
	}
	// Keep a recognized name even for extensionless HBC discovery.
	name := filepath.Base(input)
	if filepath.Ext(name) == "" {
		name += ".hbc"
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	a.tempDir = dir
	if scan, scanErr := apkloader.ScanHermesContext(ctx, dir); scan != nil {
		a.bundleFindings = scan.Findings
		a.bundleScan = scan
		a.bundleScanSeconds = time.Since(started).Seconds()
		if scanErr != nil {
			a.output.Warning("Bundle coverage incomplete: %v", scanErr)
		}
	}
	a.output.Info("Standalone bundle: %s (content-checked JS/Hermes scan)", input)
	return dir, nil
}

type staticOutputStage = types.StaticOutputStage

// runStaticOutputs never modifies an uploaded bundle or emits Hermes as JS.
// Stage errors are persisted; the caller still writes analysis reports.
func (a *App) runStaticOutputs(ctx context.Context, target, output string) error {
	if !a.opts.SaveDecoded && !a.opts.BundleExport && !a.opts.BundlePatches {
		return nil
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}
	stages := []staticOutputStage{}
	var errs []error
	if a.opts.SaveDecoded {
		stage := staticOutputStage{Stage: "decoded_apk", Status: "complete", Path: "decoded"}
		// Decode the original archive, not the IR-only extracted temp directory.
		decoded, err := decompiler.Decode(ctx, a.opts.Target, decompiler.Options{
			OutputDir: filepath.Join(output, "decoded"), Backend: decompiler.Backend(a.opts.DexBackend),
			Standalone: a.opts.Standalone, NoResources: a.opts.NoResources, NoSmali: a.opts.NoSmali,
			Headers: a.opts.SmaliHeaders && !a.opts.NoSmaliHeaders, JavaView: a.opts.JavaView,
			CopyOriginal: a.opts.CopyOriginal, ClassCache: a.opts.ClassCache,
			FrameworkDir: a.opts.FrameworkDir,
		})
		stage.Diagnostics = append(stage.Diagnostics, decoded.Warnings...)
		if err != nil {
			stage.Status = "failed"
			stage.Diagnostics = append(stage.Diagnostics, err.Error())
			errs = append(errs, err)
		}
		stages = append(stages, stage)
	}
	if a.opts.BundleExport || a.opts.BundlePatches {
		scan := a.bundleScan
		var scanErr error
		if scan == nil {
			scan, scanErr = apkloader.ScanHermesContext(ctx, target)
		}
		if scan == nil {
			scan = &apkloader.BundleScanResult{}
		}
		if scanErr != nil {
			errs = append(errs, scanErr)
			stages = append(stages, staticOutputStage{Stage: "bundle_discovery", Status: "partial", Diagnostics: []string{scanErr.Error()}})
		}
		for _, bundle := range scan.Files {
			if err := ctx.Err(); err != nil {
				errs = append(errs, err)
				break
			}
			rel := filepath.Clean(bundle.Path)
			if !filepath.IsLocal(rel) {
				errs = append(errs, fmt.Errorf("unsafe bundle path: %q", rel))
				continue
			}
			input := filepath.Join(target, rel)
			if a.opts.BundleExport {
				outRel := filepath.Join("bundles", rel+".export")
				limits, budgetErr := apkloader.BundleBudget(a.opts.BundleBudget)
				if budgetErr != nil {
					return budgetErr
				}
				coverage, err := apkloader.ExportBundleWithOptions(ctx, input, filepath.Join(output, outRel), limits)
				stages = append(stages, staticOutputStage{Stage: "bundle_export", Status: coverage.Status, Path: filepath.ToSlash(outRel), Diagnostics: coverage.Diagnostics, Export: coverage.Export})
				if err != nil {
					errs = append(errs, err)
				}
			}
			if a.opts.BundlePatches {
				if bundle.Kind != "javascript" && bundle.Kind != "hermes_bytecode" {
					stages = append(stages, staticOutputStage{Stage: "bundle_patch_candidates", Status: "unsupported", Diagnostics: []string{"Not JS/Hermes; binary asset containers must not be text-patched"}})
					continue
				}
				outRel := filepath.Join("bundle_patches", rel+".report")
				cfg := jspatcher.DefaultConfig()
				cfg.Apply = jspatcher.ApplyDryRun
				cfg.HermesBudget = a.opts.BundleBudget
				cfg.OutputDir = filepath.Join(output, outRel)
				stage := staticOutputStage{Stage: "bundle_patch_candidates", Status: "complete", Path: filepath.ToSlash(outRel)}
				result, err := jspatcher.NewPatcher(cfg).PatchFileContext(ctx, input)
				if err == nil {
					err = os.MkdirAll(cfg.OutputDir, 0755)
					if err == nil {
						_, err = jspatcher.GenerateMarkdownReport(result, cfg.OutputDir)
					}
					if err == nil {
						_, err = jspatcher.GenerateJSONReport(result, cfg.OutputDir)
					}
					if len(result.Hermes) > 0 {
						g := result.Hermes[0].GraphCoverage
						stage.TotalFunctions, stage.DecodedFunctions, stage.TotalCalls, stage.RecordedCalls = g.TotalFunctions, g.DecodedFunctions, g.Calls, g.RecordedCalls
					}
					if result.IsHermes {
						stage.Status = "scan_only"
						stage.Diagnostics = append(stage.Diagnostics, "Hermes bytecode is not patched or recompiled; no patched APK was generated")
					}
					if result.AnalysisStatus != "" && result.AnalysisStatus != "complete" {
						stage.Status = result.AnalysisStatus
					}
					stage.Diagnostics = append(stage.Diagnostics, result.Diagnostics...)
					stage.Diagnostics = append(stage.Diagnostics, result.Errors...)
					if len(result.Errors) > 0 && (stage.Status == "complete" || stage.Status == "scan_only") {
						stage.Status = "partial"
					}
				}
				if err != nil {
					stage.Status = "failed"
					stage.Diagnostics = append(stage.Diagnostics, err.Error())
					errs = append(errs, err)
				}
				stages = append(stages, stage)
			}
		}
		if len(scan.Files) == 0 {
			stages = append(stages, staticOutputStage{Stage: "bundles", Status: "not_found"})
		}
	}
	a.staticOutputs = stages
	manifest, err := json.MarshalIndent(stages, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(output, "static_outputs.json"), manifest, 0644)
	}
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
