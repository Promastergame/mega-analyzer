package apkloader

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/boundedfile"
	"mega-analyzer/pkg/internal/types"
)

// DecodeOptions controls how DecodeAPK behaves (apktool-style decode).
type DecodeOptions struct {
	OutputDir      string           // destination directory (created if missing)
	NoResources    bool             // skip AndroidManifest.xml, resources.arsc and res XML decoding
	NoSmali        bool             // skip DEX → smali conversion
	NoSmaliHeaders bool             // skip # Disassembled from DEX comment headers in smali
	SmaliHeaders   bool             // include comment headers for this decode only; NoSmaliHeaders takes precedence
	Standalone     bool             // disallow external tools for this call without changing process policy
	FrameworkDir   string           // framework directory path (placeholder for apktool compat)
	CopyOriginal   bool             // preserve original META-INF into original/ for rebuild fidelity
	DexBackend     DecompileBackend // native or auto; empty means auto
	ClassCache     bool             // cache native DEX→Smali per class when OutputDir is stable
	JavaView       bool             // emit per-class .java pseudocode next to smali
}

// DecodeAPK extracts an APK to a directory without running security analysis.
// It mirrors apktool decode: resources are decoded, DEX is converted to smali,
// and the resulting directory tree is ready for inspection or rebuilding.
func (e *Extractor) DecodeAPK(ctx context.Context, apkPath string, opts DecodeOptions) (string, error) {
	return e.decodeInput(ctx, apkPath, opts, false)
}

// DecodeDEX materializes a single DEX as a rebuildable project with classes.dex
// and smali/. It does not run artifact or security analysis.
func (e *Extractor) DecodeDEX(ctx context.Context, dexPath string, opts DecodeOptions) (string, error) {
	return e.decodeInput(ctx, dexPath, opts, true)
}

func (e *Extractor) decodeInput(ctx context.Context, apkPath string, opts DecodeOptions, rawDEX bool) (string, error) {
	e.resetState()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch opts.DexBackend {
	case "", DecompileBackendAuto, DecompileBackendNative:
		opts.DexBackend = DecompileBackendNative
	default:
		return "", fmt.Errorf("unknown decode backend %q", opts.DexBackend)
	}

	outDir := opts.OutputDir
	ownsOutputDir := false
	if outDir == "" {
		var err error
		outDir, err = os.MkdirTemp(e.TempDir, "apk_decode_*")
		if err != nil {
			return "", &LoaderError{Op: "mkdir_temp", err: err}
		}
		ownsOutputDir = true
	} else {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return "", &LoaderError{Op: "mkdir_out", Path: outDir, err: err}
		}
	}

	cacheMeta, cacheErr := buildDecodeCacheMetadataContext(ctx, apkPath, opts)
	if err := ctx.Err(); err != nil {
		return outDir, err
	}
	if cacheErr == nil && !ownsOutputDir && decodeCacheHit(outDir, cacheMeta, opts) {
		return outDir, nil
	}

	// Invalidate the previous success marker before changing any artifacts.
	// A failed decode must not leave a cache hit for an older input.
	if err := os.Remove(filepath.Join(outDir, decodeCacheFile)); err != nil && !os.IsNotExist(err) {
		return outDir, &LoaderError{Op: "invalidate_decode_cache", Path: outDir, err: err}
	}

	// 1. Extract raw ZIP contents or preserve the standalone DEX.
	var extractErr error
	if rawDEX {
		extractErr = copyDecodeDEX(ctx, apkPath, filepath.Join(outDir, "classes.dex"))
		if extractErr == nil {
			e.ensurePlaceholderManifest(outDir)
		}
	} else {
		extractErr = e.extractZipSafe(ctx, apkPath, outDir)
	}
	if extractErr != nil {
		if ownsOutputDir {
			_ = os.RemoveAll(outDir)
			return "", &LoaderError{Op: "extract_input", Path: apkPath, err: extractErr}
		}
		return outDir, &LoaderError{Op: "extract_input", Path: apkPath, err: extractErr}
	}

	// 1b. Multi-APK (XAPK / APKS / APKM / AAB) bundle support: if outDir contains APK files (1 or more), merge/extract them!
	apkFiles := e.findAPKFiles(outDir)
	if len(apkFiles) >= 1 {
		e.warn("[merger] detected %d APK file(s) in decode, merging...", len(apkFiles))
		mergedDir, err := os.MkdirTemp(e.TempDir, "apk_merged_*")
		if err != nil {
			return outDir, &LoaderError{Op: "merge_apk", Path: apkPath, err: err}
		}
		merger := NewSplitMerger(e.TempDir)
		mergeErr := merger.Merge(ctx, e, apkFiles, mergedDir)
		if mergeErr == nil {
			mergeErr = copyDir(mergedDir, outDir)
		}
		_ = os.RemoveAll(mergedDir)
		if mergeErr != nil {
			return outDir, &LoaderError{Op: "merge_apk", Path: apkPath, err: mergeErr}
		}
		for _, f := range apkFiles {
			_ = os.Remove(f)
		}
	}

	// Resources and DEX write to disjoint output trees and can be decoded in
	// parallel after extraction has completed.
	var decodeWG sync.WaitGroup
	var resourceErr, dexErr error
	if !opts.NoResources {
		decodeWG.Add(1)
		go func() {
			defer decodeWG.Done()
			resourceErr = e.decodeResourcesInPlace(ctx, outDir)
		}()
	}
	if !opts.NoSmali {
		decodeWG.Add(1)
		go func() {
			defer decodeWG.Done()
			dexErr = e.decodeDEXFiles(ctx, outDir, opts)
		}()
	}
	decodeWG.Wait()
	if err := errors.Join(resourceErr, dexErr, ctx.Err()); err != nil {
		// Never record a successful decode cache or build snapshot for a
		// partial result. The directory remains available for diagnostics.
		return outDir, &LoaderError{Op: "decode", Path: apkPath, err: err}
	}
	if !opts.NoSmali {
		RecordSmaliSnapshot(outDir)
	}

	// 4. Copy-original mode: keep original META-INF for rebuild fidelity
	if opts.CopyOriginal {
		metaInf := filepath.Join(outDir, "META-INF")
		if _, err := os.Stat(metaInf); err == nil {
			originalMeta := filepath.Join(outDir, "original", "META-INF")
			if err := os.MkdirAll(filepath.Dir(originalMeta), 0755); err == nil {
				if err := copyDir(metaInf, originalMeta); err != nil {
					e.warn("copy-original META-INF: %v", err)
				}
			}
		}
	}

	// 5. Write omnisec meta file so rebuilders know package info
	if err := e.writeDecodeMeta(outDir); err != nil {
		e.warn("write meta: %v", err)
	}
	if cacheErr == nil && !ownsOutputDir {
		if err := writeDecodeCacheMetadata(outDir, cacheMeta); err != nil {
			e.warn("write decode cache metadata: %v", err)
		}
	}

	return outDir, nil
}

func (e *Extractor) decodeDEXFiles(ctx context.Context, outDir string, opts DecodeOptions) error {
	dexFiles := e.findDEXFiles(outDir)
	if len(dexFiles) == 0 || ctx.Err() != nil {
		return ctx.Err()
	}
	sort.Strings(dexFiles)

	switch opts.DexBackend {
	case "", DecompileBackendAuto, DecompileBackendNative:
		return e.parseMultiDEXWithOptions(ctx, dexFiles, outDir, smaliOutputOptions{
			cache: opts.ClassCache, headers: opts.SmaliHeaders && !opts.NoSmaliHeaders,
			java: opts.JavaView,
		})
	default:
		return fmt.Errorf("unknown decode backend %q: use native or auto", opts.DexBackend)
	}
}

// decodeResourcesInPlace decodes manifest, resource table and res/*.xml in a
// stable order. Resource decoding is intentionally separate from concurrent
// ZIP extraction so files cannot be read while another worker is writing them.
func (e *Extractor) decodeResourcesInPlace(ctx context.Context, root string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var failures []error
	recordFailure := func(path string, err error) {
		failures = append(failures, fmt.Errorf("decode resource %s: %w", path, err))
	}
	manifestPath := filepath.Join(root, "AndroidManifest.xml")
	if info, err := os.Stat(manifestPath); err == nil && info.Mode().IsRegular() {
		decoded, decodeErr := decodeAndSaveManifest(manifestPath)
		if decodeErr != nil {
			e.warn("decode manifest: %v", decodeErr)
			recordFailure(manifestPath, decodeErr)
			if strings.Contains(decodeErr.Error(), "parser_crash") {
				e.addFinding(manifestPath, types.SeverityLow,
					"parser_crash: AndroidManifest.xml triggered a contained parser panic — input is likely malicious or malformed")
			}
		} else if decoded != nil {
			e.setManifestMeta(decoded)
			e.warn("AXML decoded: pkg=%s perms=%d activities=%d",
				decoded.Package, len(decoded.Permissions), len(decoded.Activities))
		} else if meta, metaErr := readTextManifestMeta(manifestPath); metaErr == nil {
			e.setMeta(meta)
		} else {
			e.warn("read manifest metadata: %v", metaErr)
			recordFailure(manifestPath, metaErr)
		}
	} else if err != nil && !os.IsNotExist(err) {
		recordFailure(manifestPath, err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	arscPath := filepath.Join(root, "resources.arsc")
	if info, err := os.Stat(arscPath); err == nil && info.Mode().IsRegular() {
		if err := decodeAndSaveARSC(arscPath); err != nil {
			e.warn("decode resources.arsc: %v", err)
			recordFailure(arscPath, err)
			if strings.Contains(err.Error(), "parser_crash") {
				e.addFinding(arscPath, types.SeverityLow,
					"parser_crash: resources.arsc triggered a contained parser panic — input is likely malicious or malformed")
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		recordFailure(arscPath, err)
	}

	resDir := filepath.Join(root, "res")
	walkErr := filepath.WalkDir(resDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == resDir {
				return filepath.SkipDir
			}
			e.warn("resource walk error at %s: %v", path, err)
			recordFailure(path, err)
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".xml") {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := decodeAndSaveAXML(path); err != nil {
			e.warn("decode %s: %v", filepath.Base(path), err)
			recordFailure(path, err)
		}
		return nil
	})
	return errors.Join(append(failures, walkErr, ctx.Err())...)
}

func (e *Extractor) setManifestMeta(m *axml.Manifest) {
	if m == nil {
		return
	}
	e.setMeta(&APKMeta{
		Package:     m.Package,
		VersionCode: int(m.VersionCode),
		VersionName: m.VersionName,
		MinSDK:      int(m.MinSDK),
		TargetSDK:   int(m.TargetSDK),
	})
}

const androidXMLNamespace = "http://schemas.android.com/apk/res/android"

type textManifestMeta struct {
	XMLName     xml.Name `xml:"manifest"`
	Package     string   `xml:"package,attr"`
	VersionCode string   `xml:"http://schemas.android.com/apk/res/android versionCode,attr"`
	VersionName string   `xml:"http://schemas.android.com/apk/res/android versionName,attr"`
	UsesSDK     struct {
		MinSDK    string `xml:"http://schemas.android.com/apk/res/android minSdkVersion,attr"`
		TargetSDK string `xml:"http://schemas.android.com/apk/res/android targetSdkVersion,attr"`
	} `xml:"uses-sdk"`
}

func readTextManifestMeta(path string) (*APKMeta, error) {
	data, err := boundedfile.ReadFile(path, maxXMLBytes)
	if err != nil {
		return nil, err
	}
	var raw textManifestMeta
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &APKMeta{
		Package:     raw.Package,
		VersionCode: parseManifestInt(raw.VersionCode),
		VersionName: raw.VersionName,
		MinSDK:      parseManifestInt(raw.UsesSDK.MinSDK),
		TargetSDK:   parseManifestInt(raw.UsesSDK.TargetSDK),
	}, nil
}

func parseManifestInt(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "@") {
		return 0
	}
	parsed, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0
	}
	return int(parsed)
}

// writeDecodeMeta writes an omnisec-meta.json file so downstream rebuilders
// retain package details and original compression choices.
func (e *Extractor) writeDecodeMeta(outDir string) error {
	if e.Meta == nil {
		manifestPath := filepath.Join(outDir, "AndroidManifest.xml")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return err
		}
		if axml.IsBinaryXML(data) {
			m, err := axml.Decode(data)
			if err != nil {
				return err
			}
			e.setManifestMeta(m)
		} else {
			meta, err := readTextManifestMeta(manifestPath)
			if err != nil {
				return err
			}
			e.setMeta(meta)
		}
	}
	return e.saveApkToolMeta(outDir)
}

// copyDir recursively copies src directory to dst directory.
