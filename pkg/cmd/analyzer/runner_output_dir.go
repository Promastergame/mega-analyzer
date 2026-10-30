package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const outputMarkerName = ".omnisec-output"

func writeOutputMarker(outputDir string) error {
	abs, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}
	marker := filepath.Join(abs, outputMarkerName)
	// Best-effort: never fail the run because of marker file.
	return os.WriteFile(marker, []byte("omnisec output directory\n"), 0644)
}

func cleanOutputDir(outputDir string) error {
	abs, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("cannot resolve output dir: %w", err)
	}

	abs = filepath.Clean(abs)
	base := filepath.Base(abs)

	// Refuse dangerous paths.
	if abs == "." || abs == string(os.PathSeparator) {
		return fmt.Errorf("refusing to clean unsafe output dir: %q", outputDir)
	}
	if base == "." || base == string(os.PathSeparator) || base == "" {
		return fmt.Errorf("refusing to clean unsafe output dir: %q", outputDir)
	}

	// Drive root safety (Windows).
	if vol := filepath.VolumeName(abs); vol != "" {
		root := vol + string(os.PathSeparator)
		if strings.EqualFold(abs, root) {
			return fmt.Errorf("refusing to clean drive root: %q", abs)
		}
	}

	// Only clean if it looks like our output dir.
	// Allow analysis_output even if marker doesn't exist (first run).
	// A nonexistent or empty custom directory is always safe to adopt:
	// create it and stamp the marker so future runs recognise it. Refuse
	// only a directory holding FOREIGN files without a marker, which might
	// hold data from another tool. Our own startup files (analyzer.log from
	// logger init, .cache) never block adoption: the logger creates
	// analyzer.log before this clean runs, so counting it as "foreign"
	// made every fresh custom -o dir refuse itself.
	marker := filepath.Join(abs, outputMarkerName)
	if _, markerErr := os.Stat(marker); markerErr != nil && base != "analysis_output" {
		entries, readErr := os.ReadDir(abs)
		switch {
		case readErr != nil && !os.IsNotExist(readErr):
			return fmt.Errorf("failed to read output directory: %w", readErr)
		case readErr == nil && len(nonOwnedOutputEntries(entries)) > 0:
			return fmt.Errorf("refusing to clean %q: marker %q not found and directory is not empty (run once without -clean-output to adopt it)", abs, outputMarkerName)
		default:
			// Missing, empty, or holding only our own files: adopt it.
			if mkErr := os.MkdirAll(abs, 0755); mkErr != nil {
				return fmt.Errorf("cannot create output directory: %w", mkErr)
			}
			if mkErr := writeOutputMarker(abs); mkErr != nil {
				return fmt.Errorf("cannot stamp output marker: %w", mkErr)
			}
		}
	}

	// Remove all files and folders inside the output directory
	// EXCEPT the locked analyzer.log file to support clean-output on Windows.
	entries, err := os.ReadDir(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read output directory: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if isOwnedOutputEntry(name) {
			continue // Locked log, persistent cache, ownership marker.
		}
		path := filepath.Join(abs, name)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to clean output directory at %q: %w", path, err)
		}
	}
	return nil
}

// isOwnedOutputEntry reports whether a file in the output dir is created by
// the analyzer itself: the startup log, the persistent cache, or the
// ownership marker. Owned entries are never deleted by cleaning and never
// count as "foreign data" blocking adoption of a fresh output dir.
func isOwnedOutputEntry(name string) bool {
	return name == outputMarkerName || name == "analyzer.log" || name == ".cache"
}

// nonOwnedOutputEntries filters an output-dir listing down to files that did
// not come from the analyzer itself.
func nonOwnedOutputEntries(entries []os.DirEntry) []os.DirEntry {
	kept := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		if e == nil || isOwnedOutputEntry(e.Name()) {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}
