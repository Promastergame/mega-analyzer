package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/ml/assetscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// -assets — ASSET SCAN COMMAND
//
// Deliberately not part of the analysis pipeline. Somebody asking "which .glb
// files are in this APK and what do their textures look like" should not have
// to sit through rule matching, deobfuscation and report generation first.
// ═══════════════════════════════════════════════════════════════════════════════

// assetIndexName is the report the Zig editor looks for inside a preview
// directory. Writing it unconditionally means the editor can be pointed at the
// folder later, without re-running the scan or parsing a pipe.
const assetIndexName = "assets.json"

// defaultPreviewDir puts previews next to the target rather than in the
// current working directory, so -assets-open works with no extra arguments and
// two scans of two different APKs never overwrite each other.
func defaultPreviewDir(target string) string {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	base := filepath.Base(abs)
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "target"
	}
	return filepath.Join(filepath.Dir(abs), base+"-assets")
}

// runAssetScan implements -assets.
func runAssetScan(opts *CLIOptions) error {
	target := opts.AssetScan
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("-assets: cannot read %s: %w", target, err)
	}

	// Rendering previews is the whole point of the flag, so it is on by
	// default. -assets-json alone stays read-only: a caller piping JSON into
	// another program has not asked for files to appear on disk.
	outDir := opts.AssetsOut
	if outDir == "" && (!opts.AssetsJSON || opts.AssetsOpen) {
		outDir = defaultPreviewDir(target)
	}

	rep, err := assetscan.Scan(target, assetscan.Options{
		PreviewDir:  outDir,
		MaxFileMB:   opts.AssetsMaxMB,
		MaxDim:      opts.AssetsMaxDim,
		MaxPreviews: opts.AssetsMaxPrev,
		Deep:        opts.AssetsDeep,
		All:         opts.AssetsAll,
		NoTextures:  opts.AssetsNoTextures,
		MaxTextures: opts.AssetsTextures,
		NoBytemap:   opts.AssetsNoBytemap,
		NoZstd:      opts.AssetsNoZstd,
		NoASTC:      opts.AssetsNoASTC,
	})
	if err != nil {
		return fmt.Errorf("-assets: %w", err)
	}

	blob, jsonErr := rep.JSON()
	if outDir != "" && jsonErr == nil {
		index := filepath.Join(outDir, assetIndexName)
		if werr := os.WriteFile(index, append(blob, '\n'), 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "asset scan: could not write %s: %v\n", index, werr)
		}
	}

	if opts.AssetsJSON {
		// Nothing but JSON may reach stdout here; the editor parses the pipe.
		if jsonErr != nil {
			return fmt.Errorf("-assets: encoding report: %w", jsonErr)
		}
		if _, err := os.Stdout.Write(append(blob, '\n')); err != nil {
			return err
		}
	} else {
		fmt.Print(rep.Text())
	}

	if opts.AssetsOpen {
		if err := openAssetPreviews(rep, opts.AssetsJSON); err != nil {
			// A missing GUI binary must not fail the scan: the PNGs are already
			// on disk and the report has already been delivered.
			fmt.Fprintf(os.Stderr, "asset scan: %v\n", err)
		}
	}
	return nil
}

// openAssetPreviews hands the preview directory to the native Zig editor.
func openAssetPreviews(rep *assetscan.Report, quiet bool) error {
	if rep.PreviewDir == "" {
		return fmt.Errorf("-assets-open needs a preview directory; pass -assets-out <dir>")
	}
	if err := LaunchAPKEditor(rep.PreviewDir, ""); err != nil {
		return err
	}
	if !quiet {
		fmt.Printf("\n  opened %s in the Zig APK Patch Editor\n", rep.PreviewDir)
	}
	return nil
}
