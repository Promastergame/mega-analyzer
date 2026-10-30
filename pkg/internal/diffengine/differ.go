// Package diffengine compares two versions of APK/EXE/ELF binaries and
// produces a structured diff report: added/removed/modified functions,
// changed constants, new permissions, patched instructions, etc.
package diffengine

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DIFF RESULT TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// ChangeType classifies a diff entry.
type ChangeType uint8

const (
	ChangeAdded    ChangeType = iota // present in B only
	ChangeRemoved                    // present in A only
	ChangeModified                   // present in both but different
)

func (c ChangeType) String() string {
	switch c {
	case ChangeAdded:
		return "ADDED"
	case ChangeRemoved:
		return "REMOVED"
	case ChangeModified:
		return "MODIFIED"
	}
	return "UNKNOWN"
}

// FileDiff represents a diff for a single file.
type FileDiff struct {
	Path     string
	Change   ChangeType
	HashA    string // SHA256 of version A (empty if added)
	HashB    string // SHA256 of version B (empty if removed)
	SizeA    int64
	SizeB    int64
	Category string // "code", "resource", "config", "native", "manifest"
}

// DiffReport is the complete comparison result.
type DiffReport struct {
	VersionA string
	VersionB string
	Files    []FileDiff
	Summary  DiffSummary
}

// DiffSummary holds aggregate counts.
type DiffSummary struct {
	TotalFiles    int
	Added         int
	Removed       int
	Modified      int
	Unchanged     int
	CodeChanges   int
	NativeChanges int
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIFFER ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// Differ compares two directory trees.
type Differ struct {
	IgnorePatterns []string
}

// NewDiffer creates a new diff engine.
func NewDiffer() *Differ {
	return &Differ{
		IgnorePatterns: []string{
			".git", ".DS_Store", "Thumbs.db", "__MACOSX",
		},
	}
}

// Compare produces a DiffReport from two directory trees.
func (d *Differ) Compare(pathA, pathB string) (*DiffReport, error) {
	filesA, err := d.scanDir(pathA)
	if err != nil {
		return nil, fmt.Errorf("scanning version A: %w", err)
	}
	filesB, err := d.scanDir(pathB)
	if err != nil {
		return nil, fmt.Errorf("scanning version B: %w", err)
	}

	report := &DiffReport{
		VersionA: pathA,
		VersionB: pathB,
	}

	// Build map of B files
	mapB := make(map[string]fileInfo, len(filesB))
	for _, f := range filesB {
		mapB[f.relPath] = f
	}

	seen := make(map[string]bool)

	// Check A files against B
	for _, fa := range filesA {
		seen[fa.relPath] = true
		fb, exists := mapB[fa.relPath]
		if !exists {
			report.Files = append(report.Files, FileDiff{
				Path:     fa.relPath,
				Change:   ChangeRemoved,
				HashA:    fa.hash,
				SizeA:    fa.size,
				Category: categorize(fa.relPath),
			})
			continue
		}
		if fa.hash != fb.hash {
			report.Files = append(report.Files, FileDiff{
				Path:     fa.relPath,
				Change:   ChangeModified,
				HashA:    fa.hash,
				HashB:    fb.hash,
				SizeA:    fa.size,
				SizeB:    fb.size,
				Category: categorize(fa.relPath),
			})
		}
	}

	// Files only in B (added)
	for _, fb := range filesB {
		if !seen[fb.relPath] {
			report.Files = append(report.Files, FileDiff{
				Path:     fb.relPath,
				Change:   ChangeAdded,
				HashB:    fb.hash,
				SizeB:    fb.size,
				Category: categorize(fb.relPath),
			})
		}
	}

	// Sort by path for stable output
	sort.Slice(report.Files, func(i, j int) bool {
		return report.Files[i].Path < report.Files[j].Path
	})

	// Count every path in the union once, including removed files.
	for _, fd := range report.Files {
		switch fd.Change {
		case ChangeAdded:
			report.Summary.Added++
		case ChangeRemoved:
			report.Summary.Removed++
		case ChangeModified:
			report.Summary.Modified++
		}
		if fd.Category == "code" {
			report.Summary.CodeChanges++
		}
		if fd.Category == "native" {
			report.Summary.NativeChanges++
		}
	}
	report.Summary.TotalFiles = len(filesA) + report.Summary.Added
	report.Summary.Unchanged = report.Summary.TotalFiles -
		report.Summary.Added - report.Summary.Removed - report.Summary.Modified

	return report, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

// RenderMarkdown outputs the diff report as Markdown.
func (r *DiffReport) RenderMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Binary Diff Report\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Version A | `%s` |\n", r.VersionA)
	fmt.Fprintf(&b, "| Version B | `%s` |\n", r.VersionB)
	fmt.Fprintf(&b, "| Total files | %d |\n", r.Summary.TotalFiles)
	fmt.Fprintf(&b, "| Added | **%d** |\n", r.Summary.Added)
	fmt.Fprintf(&b, "| Removed | **%d** |\n", r.Summary.Removed)
	fmt.Fprintf(&b, "| Modified | **%d** |\n", r.Summary.Modified)
	fmt.Fprintf(&b, "| Unchanged | %d |\n", r.Summary.Unchanged)
	fmt.Fprintf(&b, "| Code changes | %d |\n", r.Summary.CodeChanges)
	fmt.Fprintf(&b, "| Native changes | %d |\n\n", r.Summary.NativeChanges)

	if len(r.Files) > 0 {
		fmt.Fprintf(&b, "## Changed Files\n\n")
		fmt.Fprintf(&b, "| Status | Category | Path |\n|---|---|---|\n")
		for _, fd := range r.Files {
			var icon string
			switch fd.Change {
			case ChangeAdded:
				icon = "➕"
			case ChangeRemoved:
				icon = "➖"
			case ChangeModified:
				icon = "✏️"
			default:
				icon = "❓"
			}
			fmt.Fprintf(&b, "| %s %s | %s | `%s` |\n", icon, fd.Change, fd.Category, fd.Path)
		}
	}
	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNALS
// ═══════════════════════════════════════════════════════════════════════════════

type fileInfo struct {
	relPath string
	hash    string
	size    int64
}

func (d *Differ) scanDir(root string) ([]fileInfo, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	var files []fileInfo
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			for _, pat := range d.IgnorePatterns {
				if info.Name() == pat {
					return filepath.SkipDir
				}
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}
		files = append(files, fileInfo{relPath: rel, hash: hash, size: info.Size()})
		return nil
	})
	return files, err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func categorize(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	switch {
	case ext == ".smali" || ext == ".dex" || ext == ".class" || ext == ".java":
		return "code"
	case ext == ".so" || ext == ".dll" || ext == ".exe" || ext == ".dylib":
		return "native"
	case base == "androidmanifest.xml" || ext == ".mf":
		return "manifest"
	case ext == ".xml" || ext == ".json" || ext == ".properties" || ext == ".cfg":
		return "config"
	default:
		return "resource"
	}
}
