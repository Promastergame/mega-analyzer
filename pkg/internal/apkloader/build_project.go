package apkloader

import (
	"archive/zip"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PrepareBuildProject accepts an unpacked Android project or a ZIP containing
// one. ZIPs use the same bounded extractor as APK decoding, without decoding or
// replacing their editable Smali/resources. The caller must invoke cleanup.
func PrepareBuildProject(ctx context.Context, input string) (dir string, cleanup func(), err error) {
	cleanup = func() {}
	if err = ctx.Err(); err != nil {
		return "", cleanup, err
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return "", cleanup, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", cleanup, fmt.Errorf("build project: %w", err)
	}
	if info.IsDir() {
		err = validateBuildProject(ctx, abs)
		return abs, cleanup, err
	}
	if !info.Mode().IsRegular() || !strings.EqualFold(filepath.Ext(abs), ".zip") {
		return "", cleanup, fmt.Errorf("build input must be a project directory or .zip containing AndroidManifest.xml and Smali/DEX; decode APK files first")
	}
	// Unlike analysis, a build must not silently skip unsafe/ambiguous members.
	zr, err := zip.OpenReader(abs)
	if err != nil {
		return "", cleanup, fmt.Errorf("open project ZIP: %w", err)
	}
	for _, entry := range zr.File {
		name := strings.TrimSuffix(entry.Name, "/")
		if !fs.ValidPath(name) || !filepath.IsLocal(filepath.FromSlash(name)) || strings.ContainsAny(name, "\\:") || entry.Mode()&os.ModeSymlink != 0 {
			zr.Close()
			return "", cleanup, fmt.Errorf("unsafe project ZIP entry %q", entry.Name)
		}
	}
	zr.Close()
	stage, err := os.MkdirTemp("", "mega-build-project-*")
	if err != nil {
		return "", cleanup, err
	}
	cleanup = func() {
		// Windows indexers/antivirus may briefly hold newly extracted files.
		// Retry only this owned MkdirTemp tree, never the caller's project.
		for attempt := 0; attempt < 5; attempt++ {
			if err := os.RemoveAll(stage); err == nil || runtime.GOOS != "windows" {
				return
			}
			time.Sleep(time.Duration(attempt+1) * 25 * time.Millisecond)
		}
	}
	extractor := NewExtractor()
	if err = extractor.extractZipSafe(ctx, abs, stage); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("extract project ZIP: %w", err)
	}
	if warnings := extractor.GetWarnings(); len(warnings) != 0 {
		cleanup()
		return "", func() {}, fmt.Errorf("project ZIP was not extracted completely: %s", strings.Join(warnings, "; "))
	}
	dir, err = findBuildProjectRoot(ctx, stage)
	if err == nil {
		err = validateBuildProject(ctx, dir)
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dir, cleanup, nil
}

func findBuildProjectRoot(ctx context.Context, root string) (string, error) {
	var candidates []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "__MACOSX" {
				return filepath.SkipDir
			}
			if info, err := os.Stat(filepath.Join(path, "AndroidManifest.xml")); err == nil && info.Mode().IsRegular() {
				candidates = append(candidates, path)
				return filepath.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(candidates) != 1 {
		return "", fmt.Errorf("project ZIP must contain exactly one Android project with AndroidManifest.xml (found %d); upload one decoded or Smali project", len(candidates))
	}
	return candidates[0], nil
}

func validateBuildProject(ctx context.Context, dir string) error {
	if info, err := os.Stat(filepath.Join(dir, "AndroidManifest.xml")); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("build project requires AndroidManifest.xml at its root; Java/Kotlin/Gradle compilation is not supported; use a decoded APK or a Smali/DEX project")
	}
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// Application payload and Java-view sidecars are not source inputs.
		if entry.IsDir() && (rel == "assets" || rel == "lib" || rel == "original" || rel == "build" || rel == "smali" || strings.HasPrefix(rel, "smali_") || rel == ".git" || rel == "res/raw" || strings.HasPrefix(rel, "res/raw-")) {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("build project contains a symbolic link: %s", rel)
		}
		if !entry.IsDir() {
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".java" || ext == ".kt" || ext == ".class" || entry.Name() == "build.gradle" || entry.Name() == "build.gradle.kts" {
				return fmt.Errorf("%s: native APK build accepts Smali or precompiled DEX, not Java/Kotlin/Gradle sources; a Java/Kotlin compiler and Android API definitions would be required", rel)
			}
		}
		return nil
	})
}
