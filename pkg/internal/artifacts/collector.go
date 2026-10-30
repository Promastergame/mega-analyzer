package artifacts

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// COLLECTOR
//
// Walks the extracted APK directory and produces a deterministic list of
// artifact candidates. The actual classification + per-file enrichment
// happens later in the pipeline.

// Candidate represents a single file found on disk.
type Candidate struct {
	Path    string // path inside the extracted root
	AbsPath string // absolute path on disk
	Size    int64
	Type    Type
}

// NOTE (R2 / Item B): earlier versions also skipped directories *by name*
// when they matched analyzer output directory names (insights, mobsf,
// jspatcher, analysis_output). Those names are attacker-controlled inside an
// extracted APK - a malicious app can ship assets/mobsf/payload.js and evade
// scanning entirely. The current run's real output directory is excluded by
// absolute path (excludeDir), which the attacker cannot influence, so the
// name-based skip was removed. Pinned by TestWalk_AttackerNamedDirsAreScanned.

// Walk returns the sorted list of artifact candidates. See WalkDetailed.
func Walk(root string, excludeDir string) ([]Candidate, error) {
	out, _, err := WalkDetailed(root, excludeDir)
	return out, err
}

// WalkDetailed returns the sorted candidate list plus human-readable
// scan-coverage notes (skipped directories, walk errors) so every exclusion
// stays visible in the report instead of silently shrinking coverage. R2/R12.
//
// It excludes:
//   - symlinks (R1: they can point outside the scan root),
//   - the smali source tree (see the contract note below),
//   - excludeDir, the absolute path of the current run's output directory.
func WalkDetailed(root string, excludeDir string) ([]Candidate, []string, error) {
	if root == "" {
		return nil, nil, nil
	}
	excludeAbs := ""
	if excludeDir != "" {
		if abs, err := filepath.Abs(excludeDir); err == nil {
			excludeAbs = filepath.Clean(abs)
		}
	}
	var out []Candidate
	var notes []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Permission errors / removed files: skip, but record the
			// coverage gap instead of hiding it. R12.
			notes = append(notes, fmt.Sprintf("walk error (path skipped): %s: %v", path, err))
			return nil
		}
		// Never follow symlinks: a symlink inside the scan root can point
		// outside it (e.g. /etc/passwd) and would otherwise be read as an
		// artifact by the pipeline. filepath.Walk reports the link itself
		// (lstat), so this covers both file and directory symlinks. R1.
		if info.Mode()&os.ModeSymlink != 0 {
			notes = append(notes, "symlink (skipped): "+path)
			return nil
		}
		if info.IsDir() {
			// CONTRACT (R3 / Item A): the smali tree is deliberately out of
			// scope for the artifacts pipeline. It is the primary analysis
			// input owned by the smali static-analysis stage, not a side
			// artifact. Do NOT remove this exclusion; if the owning stage
			// ever stops covering these paths, this becomes a coverage gap.
			// Pinned by TestWalk_SmaliContract.
			name := strings.ToLower(info.Name())
			if name == "smali" || strings.HasPrefix(name, "smali_") {
				notes = append(notes, "smali tree (skipped, owned by static-analysis stage): "+path)
				return filepath.SkipDir
			}
			// Skip the exact output dir if it sits inside the scan root.
			if excludeAbs != "" {
				if abs, aerr := filepath.Abs(path); aerr == nil &&
					filepath.Clean(abs) == excludeAbs {
					notes = append(notes, "analyzer output dir (skipped): "+path)
					return filepath.SkipDir
				}
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		typ := Classify(rel, nil)
		if typ == TypeOther {
			// Unknown extension: take a bounded sniff of the file head so
			// the magic-byte classifier actually gets data to work on. R5.
			typ = Classify(rel, sniffHead(path))
		}
		if typ == TypeIgnored {
			return nil
		}

		out = append(out, Candidate{
			Path:    filepath.ToSlash(rel),
			AbsPath: path,
			Size:    info.Size(),
			Type:    typ,
		})
		return nil
	})
	if err != nil {
		return out, notes, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out, notes, nil
}

// sniffHead reads at most the first 512 bytes of the file for magic-byte
// classification. Any error just means "no data" and classification falls
// back to extension-only behaviour. R5.
func sniffHead(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := io.ReadFull(f, buf)
	return buf[:n]
}
