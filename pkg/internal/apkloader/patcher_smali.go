package apkloader

// On-demand Smali materialization for the ML patch predictor.
//
// Normal APK analysis consumes DEX through in-memory IR and never writes
// .smali files — but the patch predictor walks .smali on disk. For decoded
// directories the files already exist; for APK/XAPK targets this file
// materializes them from the extracted classes*.dex into a stable tree that
// mirrors DecodeAPK layout (smali/...), so --ml-patch works for every target
// kind. IR is streamed class by class (no Hyperion lift, no retention), so
// peak memory stays flat even for 6k-class DEX files.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// errSmaliFound aborts the discovery walk on the first hit.
var errSmaliFound = errors.New("smali file found")

// HasSmaliFiles reports whether dir contains at least one .smali file.
// It early-exits on the first hit instead of enumerating huge trees.
func HasSmaliFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".smali") {
			found = true
			return errSmaliFound
		}
		return nil
	})
	return found
}

// FindDEXFiles returns all .dex files under dir in stable sorted order.
func FindDEXFiles(dir string) []string {
	var dexFiles []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".dex") {
			dexFiles = append(dexFiles, path)
		}
		return nil
	})
	sort.Strings(dexFiles)
	return dexFiles
}

// smaliRelPathForClass maps "Lcom/foo/Bar;" to "com/foo/Bar.smali".
// Segments are sanitized for Windows-safe file names; ok=false rejects
// empty or path-escaping names.
func smaliRelPathForClass(className string) (rel string, ok bool) {
	name := strings.TrimPrefix(className, "L")
	name = strings.TrimSuffix(name, ";")
	if name == "" || strings.Contains(name, "..") {
		return "", false
	}
	segs := strings.Split(name, "/")
	for i, s := range segs {
		s = sanitizeSmaliSegment(s)
		if s == "" || s == "." {
			return "", false
		}
		segs[i] = s
	}
	return strings.Join(segs, string(filepath.Separator)) + ".smali", true
}

// sanitizeSmaliSegment keeps identifier-safe runes (inner-class $ included)
// and replaces everything else so exotic obfuscated names cannot escape the
// output tree or break Windows file creation.
func sanitizeSmaliSegment(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '_' || r == '$' || r == '.' || r == '-':
			return r
		default:
			return '_'
		}
	}, s)
}

// MaterializeSmaliTree writes one .smali file per DEX class into outDir,
// mirroring DecodeAPK layout. The first DEX wins on duplicate classes.
// outDir must be an analyzer-owned tree: each successful run refreshes its
// Smali snapshot and removes classes absent from the current input.
// It returns the number of files written; 0 with nil error means the DEX
// files contained no classes.
func MaterializeSmaliTree(ctx context.Context, dexFiles []string, outDir string) (int, error) {
	written, _, err := MaterializeSmaliTreeWithSkip(ctx, dexFiles, outDir, nil)
	return written, err
}

// MaterializeSmaliTreeWithSkip behaves like MaterializeSmaliTree but never
// writes classes for which skip(rel) is true. rel is the output-relative
// smali path with forward slashes (e.g. "com/unity3d/ads/Ad.smali"), so
// callers can reuse library-prefix matchers. It returns written and skipped
// counts; skipped classes cost no disk I/O at all.
func MaterializeSmaliTreeWithSkip(ctx context.Context, dexFiles []string, outDir string, skip func(rel string) bool) (written, skipped int, err error) {
	if len(dexFiles) == 0 {
		return 0, 0, nil
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return 0, 0, err
	}
	root, err := os.OpenRoot(outDir)
	if err != nil {
		return 0, 0, err
	}
	defer root.Close()
	seen := make(map[string]string)
	for _, dexPath := range dexFiles {
		if err := ctx.Err(); err != nil {
			return written, skipped, err
		}
		n, s, err := materializeOneDEX(ctx, dexPath, root, seen, skip)
		written += n
		skipped += s
		if err != nil {
			return written, skipped, err
		}
	}
	// Only prune after all DEX files were decoded successfully. Walk the opened
	// root so stale entries cannot redirect deletion outside the generated tree.
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(rel), ".smali") {
			return nil
		}
		if _, current := seen[materializedPathKey(rel)]; current {
			return nil
		}
		return root.Remove(rel)
	})
	return written, skipped, err
}

// planMaterializeClass maps a DEX class name to its output-relative smali
// path, honouring the optional library skip. ok=false means "do not write"
// (invalid name or skipped library class).
func planMaterializeClass(className string, skip func(rel string) bool) (rel string, ok bool) {
	rel, ok = smaliRelPathForClass(className)
	if !ok {
		return "", false
	}
	if skip != nil && skip(filepath.ToSlash(rel)) {
		return "", false
	}
	return rel, true
}

func materializedPathKey(rel string) string {
	rel = filepath.ToSlash(rel)
	if runtime.GOOS == "windows" {
		rel = strings.ToLower(rel)
	}
	return rel
}

func materializeOneDEX(ctx context.Context, dexPath string, root *os.Root, seen map[string]string, skip func(rel string) bool) (written, skipped int, err error) {
	err = WalkDEXClassIRFileBytes(ctx, dexPath, func(className string, ir []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(ir) == 0 {
			return nil
		}
		rel, ok := planMaterializeClass(className, skip)
		if !ok {
			// Distinguish "invalid name" from "library skip" for honest
			// counters: only skipped libraries count as skipped.
			if _, nameOK := smaliRelPathForClass(className); nameOK {
				skipped++
			}
			return nil
		}
		key := materializedPathKey(rel)
		if firstClass, exists := seen[key]; exists {
			if firstClass != className {
				return fmt.Errorf("Smali path collision: %q and %q map to %q", firstClass, className, rel)
			}
			return nil // first DEX in this run wins; count unique files only
		}
		if info, statErr := root.Lstat(rel); statErr == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("Smali destination is not a regular file: %s", rel)
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		if mkErr := root.MkdirAll(filepath.Dir(rel), 0755); mkErr != nil {
			return mkErr
		}
		if wErr := root.WriteFile(rel, ir, 0644); wErr != nil {
			return wErr
		}
		seen[key] = className
		written++
		return nil
	})
	return written, skipped, err
}

// PruneSkippedSmali removes previously materialized files under outDir that
// the current skip predicate rejects (e.g. library trees left over from an
// earlier run with library inclusion on). Only files inside outDir — the
// analyzer-owned patcher_smali tree, never a user-supplied decoded tree —
// are candidates. It returns the number of removed files.
func PruneSkippedSmali(outDir string, skip func(rel string) bool) (removed int) {
	if skip == nil {
		return 0
	}
	_ = filepath.WalkDir(outDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".smali") {
			return nil
		}
		rel, relErr := filepath.Rel(outDir, path)
		if relErr != nil {
			return nil
		}
		if skip(filepath.ToSlash(rel)) {
			if rmErr := os.Remove(path); rmErr == nil {
				removed++
			}
		}
		return nil
	})
	return removed
}
