package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/ml"
)

// Materialized Smali and original DEX images may live in different trees.
type patchSources struct {
	SmaliDir string
	DEXDir   string
}

func (a *App) preparePatchSources(ctx context.Context, targetDir, outputDir string) (patchSources, error) {
	sources := patchSources{SmaliDir: targetDir, DEXDir: targetDir}
	if apkloader.HasSmaliFiles(targetDir) {
		return sources, nil
	}
	dexFiles, err := findDEXFiles(targetDir)
	if err != nil {
		return sources, err
	}
	if len(dexFiles) == 0 {
		return sources, nil
	}
	matDir := filepath.Join(outputDir, "patcher_smali")
	a.output.Info("Materializing %d DEX file(s) to .smali for the patch predictor...", len(dexFiles))
	var skipLibs func(string) bool
	if !a.opts.MLPatchIncludeLibs {
		skipLibs = func(rel string) bool { return ml.IsKnownLibrary(rel) }
	}
	n, skipped, err := apkloader.MaterializeSmaliTreeWithSkip(ctx, dexFiles, matDir, skipLibs)
	if err != nil {
		return sources, fmt.Errorf("materialize smali for patcher: %w", err)
	}
	if n == 0 {
		return sources, fmt.Errorf("DEX materialization produced no smali files in %s", matDir)
	}
	a.output.Info("Materialized %d smali files to %s (%d library files skipped)", n, matDir, skipped)
	sources.SmaliDir = matDir
	return sources, nil
}

type patchApplyResult struct {
	PatchID string `json:"patch_id,omitempty"`
	Method  string `json:"method"`
	File    string `json:"file"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

type patchApplySummary struct {
	Backend        string             `json:"backend"`
	Applied        int                `json:"applied"`
	AlreadyApplied int                `json:"already_applied"`
	Skipped        int                `json:"skipped"`
	Failed         int                `json:"failed"`
	Results        []patchApplyResult `json:"results"`
}

func (a *App) applyPatchesDEX(artifacts []*ml.PatchArtifact, targetDir string) error {
	_, err := a.applyPatchBatch(artifacts, patchSources{DEXDir: targetDir}, "dex")
	return err
}

func (a *App) applyPatchBatch(artifacts []*ml.PatchArtifact, sources patchSources, backend string) (*patchApplySummary, error) {
	report := &patchApplySummary{Backend: backend, Results: make([]patchApplyResult, 0, len(artifacts))}
	var dexFiles []string
	var dexErr error
	if backend == "dex" && len(artifacts) > 0 {
		dexFiles, dexErr = findDEXFiles(sources.DEXDir)
		if dexErr == nil && len(dexFiles) == 0 {
			dexErr = fmt.Errorf("no DEX files found in %s", sources.DEXDir)
		}
	}
	var failures []error
	for _, artifact := range artifacts {
		result := patchApplyResult{Status: "failed"}
		var changed bool
		var err error
		if artifact == nil {
			err = fmt.Errorf("patch artifact is missing")
		} else {
			result.PatchID, result.Method, result.File = artifact.PatchID, artifact.MethodSignature, artifact.FilePath
			if !artifact.ApplySafety.CanWrite {
				result.Status = "skipped"
				result.Reason = "patch is not safe to apply: " + strings.Join(artifact.ApplySafety.Reasons, "; ")
				report.Skipped++
				report.Results = append(report.Results, result)
				continue
			}
			switch backend {
			case "dex":
				if dexErr != nil {
					err = dexErr
					break
				}
				var descriptor, dexFile string
				descriptor, err = artifactMethodDescriptor(artifact)
				if err == nil {
					dexFile, err = findDEXForDescriptor(dexFiles, descriptor)
				}
				if err == nil {
					result.File = dexFile
					changed, err = a.applyPatchToDEXResult(artifact, dexFile)
				}
			case "smali":
				changed, err = ml.ApplyArtifactToBaseWithResult(sources.SmaliDir, artifact)
			default:
				err = fmt.Errorf("unsupported patch backend %q", backend)
			}
		}
		if err != nil {
			result.Reason = err.Error()
			report.Failed++
			failures = append(failures, fmt.Errorf("%s: %w", result.Method, err))
		} else if changed {
			result.Status = "applied"
			report.Applied++
		} else {
			result.Status = "already_applied"
			report.AlreadyApplied++
		}
		report.Results = append(report.Results, result)
	}
	if a.output != nil {
		a.output.Info("%s backend: applied %d, already applied %d, skipped %d, failed %d", backend, report.Applied, report.AlreadyApplied, report.Skipped, report.Failed)
	}
	if report.Failed > 0 {
		return report, fmt.Errorf("%d patch(es) failed: %w", report.Failed, errors.Join(failures...))
	}
	if report.Skipped > 0 && report.Applied+report.AlreadyApplied == 0 {
		return report, fmt.Errorf("no requested patches could be applied; %d skipped", report.Skipped)
	}
	return report, nil
}

func findDEXFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".dex") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func findDEXForDescriptor(files []string, descriptor string) (string, error) {
	className, _, ok := strings.Cut(descriptor, "->")
	if !ok {
		return "", fmt.Errorf("exact method descriptor is required")
	}
	var match string
	var readErrors []error
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			readErrors = append(readErrors, err)
			continue
		}
		p, err := apkloader.ParseDEXBytes(data)
		if err != nil {
			readErrors = append(readErrors, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if p.FindClassByName(className) == nil {
			continue
		}
		if match != "" {
			return "", fmt.Errorf("class %s exists in multiple DEX files", className)
		}
		match = path
	}
	if match == "" {
		if len(readErrors) > 0 {
			return "", fmt.Errorf("no DEX containing %s: %w", className, errors.Join(readErrors...))
		}
		return "", fmt.Errorf("no DEX containing %s", className)
	}
	return match, nil
}

func (a *App) applyPatchToDEX(artifact *ml.PatchArtifact, dexFile string) error {
	_, err := a.applyPatchToDEXResult(artifact, dexFile)
	return err
}

func (a *App) applyPatchToDEXResult(artifact *ml.PatchArtifact, dexFile string) (bool, error) {
	original, patched, err := artifact.ValidatedBodies()
	if err != nil {
		return false, err
	}
	descriptor, err := artifactMethodDescriptor(artifact)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(dexFile)
	if err != nil {
		return false, fmt.Errorf("read DEX: %w", err)
	}
	result, changed, err := apkloader.PatchDEXMethod(data, descriptor, original, patched)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if err := apkloader.WritePatchedDEX(dexFile, data, result); err != nil {
		return false, err
	}
	return true, nil
}

func artifactMethodDescriptor(artifact *ml.PatchArtifact) (string, error) {
	if artifact == nil {
		return "", fmt.Errorf("patch artifact is missing")
	}
	signature := strings.TrimSpace(artifact.MethodSignature)
	if signature == "" {
		for _, line := range strings.Split(artifact.OriginalCode, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), ".method ") {
				parts := strings.Fields(line)
				signature = parts[len(parts)-1]
				break
			}
		}
	}
	if !strings.Contains(signature, "(") {
		return "", fmt.Errorf("exact method signature is required")
	}
	if strings.Contains(signature, "->") {
		return signature, nil
	}
	parts := strings.Fields(signature)
	signature = parts[len(parts)-1]
	if strings.HasPrefix(signature, "(") {
		signature = artifact.MethodName + signature
	}
	if strings.HasPrefix(signature, "(") {
		return "", fmt.Errorf("method name is missing")
	}
	className := classNameFromSmaliPath(artifact.FilePath)
	if className == "" {
		return "", fmt.Errorf("cannot resolve class from %s", artifact.FilePath)
	}
	return className + "->" + signature, nil
}

func classNameFromSmaliPath(path string) string {
	norm := strings.ReplaceAll(path, "\\", "/")
	parts := strings.Split(norm, "/")
	for i, part := range parts {
		isRoot := part == "smali"
		if suffix, ok := strings.CutPrefix(part, "smali_classes"); ok && suffix != "" {
			isRoot = true
			for _, r := range suffix {
				if r < '0' || r > '9' {
					isRoot = false
					break
				}
			}
		}
		if isRoot {
			norm = strings.Join(parts[i+1:], "/")
			break
		}
	}
	if !strings.HasSuffix(norm, ".smali") || strings.HasPrefix(norm, "/") || strings.Contains(norm, ":") || strings.Contains(norm, "..") {
		return ""
	}
	name := strings.TrimSuffix(norm, ".smali")
	if name == "" {
		return ""
	}
	return "L" + name + ";"
}
