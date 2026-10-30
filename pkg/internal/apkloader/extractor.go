package apkloader

import (
	"mega-analyzer/pkg/internal/appconfig"

	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/apkloader/obb"
	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/jarloader"
	"mega-analyzer/pkg/internal/types"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	maxExtractSize = 5 * 1024 * 1024 * 1024
	maxSingleFile  = 3 * 1024 * 1024 * 1024
	maxFileCount   = 200_000
	maxZipRatio    = 10000.0
	// heuristicScanLimit caps bytes read per artifact during pattern scanning.
	// Injected payloads and loaders front-load their code, so 4 MB
	// covers the relevant region without reading entire large files.
	heuristicScanLimit = 4 * 1024 * 1024
	maxAuditFiles      = 50_000
)

// AnalysisPolicy controls how PrepareInput reacts to findings.
type AnalysisPolicy struct {
	// FailOnHighRisk aborts PrepareInput when any HIGH_RISK finding is recorded.
	FailOnHighRisk bool
	// FailOnSuspect aborts PrepareInput on SUSPECT or higher.
	FailOnSuspect bool
}

// DefaultPolicy вЂ” collect findings, never abort. Callers inspect GetFindings().
var DefaultPolicy = AnalysisPolicy{}

// suspiciousPatterns are heuristic byte sequences found in malicious
// runtime artifacts. These are indicators, not verdicts.
// Binary files will produce false positives вЂ” all results are SUSPECT
// until manually triaged.
var suspiciousPatterns = [][]byte{
	[]byte("Runtime.getRuntime().exec"),
	[]byte("/system/bin/sh"),
	[]byte("su -c"),
	[]byte("pm install"),
	[]byte("reverse_tcp"),
	[]byte("meterpreter"),
	[]byte("metasploit"),
	[]byte("payload"),
	[]byte("/dev/tcp/"),
	[]byte("keylogger"),
	[]byte("android.permission.SEND_SMS"),
	[]byte("android.permission.READ_SMS"),
	[]byte("chmod 777"),
}

// Extractor handles extraction, decompilation, and artifact analysis.
type Extractor struct {
	stateMu       sync.Mutex
	TempDir       string
	Policy        AnalysisPolicy
	Warnings      []string
	Findings      []types.ArtifactFinding
	DoNotCompress map[string]bool    // extensions stored uncompressed in original APK
	UnknownFiles  []string           // files outside res/, assets/, smali/, dex, manifest
	Meta          *APKMeta           // populated during extraction
	NativeSoPaths []string           // cached paths to .so files found during extraction
	CrackPoints   []types.CrackPoint // license/premium/tamper gates from JAR & native scans
	nativeData    map[string][]byte  // bytes scanned by analyzeNativeSo, reused by runWeaponization
}

func NewExtractor() *Extractor {
	return &Extractor{
		TempDir:       os.TempDir(),
		Policy:        DefaultPolicy,
		Warnings:      make([]string, 0),
		Findings:      make([]types.ArtifactFinding, 0),
		DoNotCompress: make(map[string]bool),
		UnknownFiles:  make([]string, 0),
	}
}

// resetState clears accumulated findings and warnings before each run.
func (e *Extractor) resetState() {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.Warnings = e.Warnings[:0]
	e.Findings = e.Findings[:0]
	e.DoNotCompress = make(map[string]bool)
	e.UnknownFiles = e.UnknownFiles[:0]
	e.Meta = nil
	e.NativeSoPaths = e.NativeSoPaths[:0]
	e.CrackPoints = e.CrackPoints[:0]
	e.nativeData = nil
}

func (e *Extractor) PrepareInput(ctx context.Context, inputPath string) (string, error) {
	return e.PrepareInputWithOptions(ctx, inputPath, PrepareOptions{})
}

// PrepareOptions is reserved for analysis-only extraction options. Analysis
// always preserves DEX files and never writes Smali; DecodeAPK is the sole API
// that performs DEX-to-Smali materialisation.
type PrepareOptions struct{}

func (e *Extractor) PrepareInputWithOptions(ctx context.Context, inputPath string, opts PrepareOptions) (string, error) {
	e.resetState()
	_ = opts
	if err := ctx.Err(); err != nil {
		return "", err
	}

	inputType, err := DetectInputType(inputPath)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	var result string

	switch inputType {
	case InputTypeSmaliFolder:
		result = inputPath

	case InputTypeCacheFolder:
		e.analyzeArtifacts(inputPath)
		result = inputPath

	case InputTypeAPKFile:
		result, err = e.extractAPK(ctx, inputPath)

	case InputTypeDEXFile:
		result, err = e.decompileDEX(ctx, inputPath)

	case InputTypeArchiveFile:
		result, err = e.extractArchive(ctx, inputPath)

	case InputTypePatchFile:
		result, err = e.analyzePatch(ctx, inputPath)

	default:
		return "", &LoaderError{Op: "prepare", Path: inputPath, err: errUnknownFormat}
	}

	if err != nil {
		return "", err
	}

	// Phase: ML-Apli-Ex 1-4 (Autonomous Exploitation)
	// Runs AFTER the initial scan/extraction.
	e.runWeaponization(result)

	if policyErr := e.applyPolicy(inputPath); policyErr != nil {
		return "", policyErr
	}

	return result, nil
}

// applyPolicy checks collected findings against the configured policy.
func (e *Extractor) applyPolicy(inputPath string) error {
	if !e.Policy.FailOnHighRisk && !e.Policy.FailOnSuspect {
		return nil
	}
	for _, f := range e.Findings {
		if e.Policy.FailOnHighRisk && f.Severity == types.SeverityHigh {
			return &LoaderError{
				Op:   "policy",
				Path: inputPath,
				err:  fmt.Errorf("HIGH_RISK artifact: %s вЂ” %s", f.Path, f.Reason),
			}
		}
		if e.Policy.FailOnSuspect &&
			(f.Severity == types.SeverityMedium || f.Severity == types.SeverityHigh) {
			return &LoaderError{
				Op:   "policy",
				Path: inputPath,
				err:  fmt.Errorf("SUSPECT artifact: %s вЂ” %s", f.Path, f.Reason),
			}
		}
	}
	return nil
}

func (e *Extractor) extractAPK(ctx context.Context, apkPath string) (string, error) {
	return e.extractZipBundle(ctx, apkPath, "extract_apk")
}

func (e *Extractor) extractArchive(ctx context.Context, archivePath string) (string, error) {
	return e.extractZipBundle(ctx, archivePath, "extract_archive")
}

func (e *Extractor) extractZipBundle(ctx context.Context, archivePath, op string) (string, error) {
	tempDir, err := os.MkdirTemp(e.TempDir, "apk_extract_*")
	if err != nil {
		return "", &LoaderError{Op: "mkdir_temp", err: err}
	}

	if err := e.extractZipSafe(ctx, archivePath, tempDir); err != nil {
		os.RemoveAll(tempDir)
		return "", &LoaderError{Op: op, err: err}
	}

	if isJavaArchiveName(archivePath) {
		e.analyzeJavaArchive(archivePath)
	}

	// AAB / Split APK / XAPK support: if tempDir contains APK files (1 or more), extract/merge them!
	apkFiles := e.findAPKFiles(tempDir)
	if len(apkFiles) >= 1 {
		e.warn("[merger] detected %d APK file(s) in bundle, merging...", len(apkFiles))
		mergedDir, err := os.MkdirTemp(e.TempDir, "apk_merged_*")
		if err != nil {
			os.RemoveAll(tempDir)
			return "", &LoaderError{Op: "mkdir_temp", err: err}
		}

		merger := NewSplitMerger(e.TempDir)
		if err := merger.Merge(ctx, e, apkFiles, mergedDir); err != nil {
			os.RemoveAll(tempDir)
			os.RemoveAll(mergedDir)
			return "", fmt.Errorf("split APK merge failed: %w", err)
		}

		// Clean up the original extracted split APK files
		os.RemoveAll(tempDir)
		tempDir = mergedDir
	}

	// Split merging can replace the base manifest and add resources. Run the
	// idempotent decoder once more so metadata always reflects the merged tree.
	if err := e.decodeResourcesInPlace(ctx, tempDir); err != nil {
		os.RemoveAll(tempDir)
		return "", &LoaderError{Op: op, Path: archivePath, err: err}
	}
	if err := e.saveApkToolMeta(tempDir); err != nil {
		e.warn("save omnisec-meta.json: %v", err)
	}

	// Analyze cache and patch artifacts inside the extracted tree.
	// APK assets/lib/oat directories are a known hiding spot for
	// injected runtime code that developers rarely review.
	e.analyzeArtifacts(tempDir)

	// React Native / Hermes bytecode bundle scan
	if bundleScan, err := ScanHermesContext(ctx, tempDir); bundleScan != nil {
		e.addFindings(bundleScan.Findings)
		if err != nil {
			e.warn("bundle analysis incomplete: %v", err)
		}
	}

	if hasSmaliFiles(tempDir) {
		return tempDir, nil
	}

	dexFiles := e.findDEXFiles(tempDir)
	if len(dexFiles) > 0 {
		// Analysis consumes classes*.dex directly through the pipeline's
		// in-memory DEX IR. Never materialise Smali here.
		return tempDir, nil
	}

	if hasSupportedAnalysisFiles(tempDir) {
		return tempDir, nil
	}

	os.RemoveAll(tempDir)
	return "", &LoaderError{Op: op, err: errArchiveNoSupportedFiles}
}

func (e *Extractor) extractZipSafe(ctx context.Context, zipPath, destDir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	if len(r.File) > maxFileCount {
		return errZipBomb
	}

	destDir, err = filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("resolve extraction directory: %w", err)
	}
	jobsList, err := e.planZipExtraction(r.File, destDir)
	if err != nil {
		return err
	}

	var (
		eMu     sync.Mutex
		mkdirMu sync.Mutex
	)
	safeTrackNoCompress := func(ext string) {
		eMu.Lock()
		defer eMu.Unlock()
		e.DoNotCompress[ext] = true
	}
	safeTrackUnknown := func(name string) {
		eMu.Lock()
		defer eMu.Unlock()
		e.UnknownFiles = append(e.UnknownFiles, name)
	}

	workersCount := runtime.NumCPU()
	if workersCount < 4 {
		workersCount = 4
	}
	if workersCount > 16 {
		workersCount = 16
	}
	if workersCount > len(jobsList) {
		workersCount = len(jobsList)
	}

	jobs := make(chan zipExtractJob, len(jobsList))
	for _, job := range jobsList {
		jobs <- job
	}
	close(jobs)

	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
		budget   atomic.Int64
	)
	budget.Store(int64(maxExtractSize))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Per-worker reusable 256 KB copy buffer вЂ” avoids io.Copy
			// allocating a fresh 32 KB buffer on every single entry.
			copyBuf := make([]byte, 256*1024)
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				f := job.file
				if job.isDir {
					mkdirMu.Lock()
					mkErr := os.MkdirAll(job.path, 0755)
					mkdirMu.Unlock()
					if mkErr != nil {
						fail(fmt.Errorf("create directory for %q: %w", f.Name, mkErr))
						return
					}
					continue
				}

				mkdirMu.Lock()
				err := os.MkdirAll(filepath.Dir(job.path), 0755)
				mkdirMu.Unlock()
				if err != nil {
					fail(fmt.Errorf("create parent for %q: %w", f.Name, err))
					return
				}

				_, err = extractZipFile(f, job.path, copyBuf, &budget)
				if err != nil {
					fail(fmt.Errorf("extract %q: %w", f.Name, err))
					return
				}

				if f.Method == zip.Store {
					ext := strings.ToLower(filepath.Ext(f.Name))
					if ext != "" {
						ext = ext[1:]
						if !noCompressExts[ext] {
							safeTrackNoCompress(ext)
						}
					}
				}

				if e.isUnknownFile(f.Name) {
					safeTrackUnknown(f.Name)
				}
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

type zipExtractJob struct {
	file  *zip.File
	path  string
	isDir bool
}

// planZipExtraction validates central-directory metadata before any file is
// written and resolves every entry to an unambiguous destination path.
func (e *Extractor) planZipExtraction(files []*zip.File, destDir string) ([]zipExtractJob, error) {
	jobs := make([]zipExtractJob, 0, len(files))
	seen := make(map[string]zipExtractJob, len(files))
	var declaredTotal uint64

	// Every directory an entry will require (itself for dirs, all ancestors
	// for everything). A file sitting on one of those paths would make the
	// later MkdirAll fail and abort the whole extraction, so such files are
	// renamed _dup upfront (obfuscated APKs ship entries "a" and "a/b").
	neededDirs := make(map[string]bool)
	for _, f := range files {
		if outPath, ok := safeZipOutputPath(destDir, f.Name); ok {
			p := filepath.ToSlash(filepath.Clean(outPath))
			if runtime.GOOS == "windows" {
				p = strings.ToLower(p)
			}
			for {
				idx := strings.LastIndexByte(p, '/')
				if idx < 0 {
					break
				}
				p = p[:idx]
				neededDirs[p] = true
			}
			if f.Mode().IsDir() {
				self := filepath.ToSlash(filepath.Clean(outPath))
				if runtime.GOOS == "windows" {
					self = strings.ToLower(self)
				}
				neededDirs[self] = true
			}
		}
	}

	for _, f := range files {
		outPath, ok := safeZipOutputPath(destDir, f.Name)
		if !ok {
			e.warn("skip unsafe ZIP path: %q", f.Name)
			continue
		}

		mode := f.Mode()
		if mode&os.ModeSymlink != 0 {
			e.warn("skip ZIP symlink: %q", f.Name)
			continue
		}
		if !mode.IsRegular() && !mode.IsDir() {
			e.warn("skip unsupported ZIP entry: %q", f.Name)
			continue
		}

		isDir := mode.IsDir()
		if !isDir {
			if f.UncompressedSize64 > uint64(maxSingleFile) {
				return nil, fmt.Errorf("%w: %q is %d bytes", errZipBomb, f.Name, f.UncompressedSize64)
			}
			if f.UncompressedSize64 > uint64(maxExtractSize)-declaredTotal {
				return nil, errZipBomb
			}
			declaredTotal += f.UncompressedSize64

			if f.CompressedSize64 > 0 {
				ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64)
				if ratio > maxZipRatio {
					return nil, fmt.Errorf("%w: %.0fx ratio in %q", errZipBomb, ratio, f.Name)
				}
			}
		}

		key := filepath.Clean(outPath)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		needsRename := neededDirs[key] && !isDir
		if previous, exists := seen[key]; exists {
			if previous.isDir && isDir {
				continue
			}
			if !isDir {
				needsRename = true
			} else if !previous.isDir {
				// A directory colliding with an already-planned file: the
				// file planner above already renamed the file (its path was
				// in neededDirs), so this only triggers when the pre-pass
				// missed it вЂ” skip the dir rather than failing MkdirAll.
				e.warn("skip ZIP directory colliding with file: %q", f.Name)
				continue
			}
		}
		if needsRename {
			// On Windows/case-insensitive filesystems, obfuscated APKs often contain entries
			// differing only in case (e.g. res/Fo.png vs res/fo.png). Disambiguate path instead of erroring out.
			ext := filepath.Ext(outPath)
			base := strings.TrimSuffix(outPath, ext)
			for counter := 1; counter <= 1000; counter++ {
				newPath := fmt.Sprintf("%s_dup%d%s", base, counter, ext)
				newKey := filepath.Clean(newPath)
				if runtime.GOOS == "windows" {
					newKey = strings.ToLower(newKey)
				}
				if _, dupExists := seen[newKey]; !dupExists && !neededDirs[newKey] {
					e.warn("disambiguated ZIP path collision: %q -> %q", f.Name, filepath.Base(newPath))
					outPath = newPath
					key = newKey
					break
				}
			}
		}
		job := zipExtractJob{file: f, path: outPath, isDir: isDir}
		seen[key] = job
		jobs = append(jobs, job)
	}

	return jobs, nil
}

func safeZipOutputPath(destDir, name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || strings.IndexByte(name, 0) >= 0 || strings.HasPrefix(name, "/") {
		return "", false
	}

	cleanName := pathpkg.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", false
	}
	// Reject Windows drive-qualified paths even when running on Unix so an
	// archive cannot become unsafe when moved between platforms.
	if len(cleanName) >= 2 && cleanName[1] == ':' {
		return "", false
	}

	relPath := filepath.FromSlash(cleanName)
	if filepath.IsAbs(relPath) || filepath.VolumeName(relPath) != "" {
		return "", false
	}
	relPath = sanitizeWindowsPath(relPath)
	outPath := filepath.Join(destDir, relPath)
	rel, err := filepath.Rel(destDir, outPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return outPath, true
}

type extractionBudgetWriter struct {
	w         io.Writer
	remaining *atomic.Int64
}

func (w extractionBudgetWriter) Write(p []byte) (int, error) {
	need := int64(len(p))
	for {
		remaining := w.remaining.Load()
		if need > remaining {
			return 0, errZipBomb
		}
		if w.remaining.CompareAndSwap(remaining, remaining-need) {
			break
		}
	}

	n, err := w.w.Write(p)
	if n < len(p) {
		w.remaining.Add(int64(len(p) - n))
	}
	return n, err
}

// extractZipFile writes through a shared extraction budget and only replaces
// the destination after the entry has passed decompression and CRC checks.
func extractZipFile(f *zip.File, outPath string, buf []byte, budget *atomic.Int64) (uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	out, err := os.CreateTemp(filepath.Dir(outPath), ".apkloader-*")
	if err != nil {
		return 0, err
	}
	tmpPath := out.Name()
	keepTemp := false
	defer func() {
		if !keepTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := out.Chmod(0644); err != nil {
		_ = out.Close()
		return 0, err
	}

	limited := io.LimitReader(rc, int64(maxSingleFile)+1)
	written, copyErr := io.CopyBuffer(extractionBudgetWriter{w: out, remaining: budget}, limited, buf)
	closeErr := out.Close()

	if copyErr != nil {
		budget.Add(written)
		return 0, copyErr
	}
	if closeErr != nil {
		budget.Add(written)
		return 0, closeErr
	}
	if written > int64(maxSingleFile) {
		budget.Add(written)
		return 0, errZipBomb
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		// Windows does not replace an existing destination with Rename.
		if _, statErr := os.Lstat(outPath); statErr != nil {
			budget.Add(written)
			return 0, err
		}
		if removeErr := os.Remove(outPath); removeErr != nil && !os.IsNotExist(removeErr) {
			budget.Add(written)
			return 0, removeErr
		}
		if err := os.Rename(tmpPath, outPath); err != nil {
			budget.Add(written)
			return 0, err
		}
	}
	keepTemp = true

	return uint64(written), nil
}

// isUnknownFile returns true when a ZIP entry is outside the standard
// APK structure (res/, assets/, smali/, lib/, dex, manifest, META-INF,
// original/, build/, unknown/). Apktool places these in unknown/.
func (e *Extractor) isUnknownFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "res/") ||
		strings.HasPrefix(lower, "assets/") ||
		strings.HasPrefix(lower, "smali") ||
		strings.HasPrefix(lower, "lib/") ||
		strings.HasPrefix(lower, "meta-inf/") ||
		strings.HasPrefix(lower, "original/") ||
		strings.HasPrefix(lower, "build/") ||
		strings.HasPrefix(lower, "unknown/") ||
		strings.HasPrefix(lower, "kotlin/") ||
		lower == "androidmanifest.xml" ||
		strings.HasSuffix(lower, ".dex") ||
		lower == "resources.arsc" ||
		lower == "omnisec-meta.json" ||
		lower == "apktool.yml" {
		return false
	}
	return true
}

// saveApkToolMeta writes omnisec-meta.json with doNotCompress, unknownFiles
// and package metadata extracted from the APK.
func (e *Extractor) saveApkToolMeta(destDir string) error {
	meta := &APKMeta{
		Tool:   "Mega-Analyzer",
		Format: "omnisec-v1",
	}
	if e.Meta != nil {
		meta.Package = e.Meta.Package
		meta.VersionCode = e.Meta.VersionCode
		meta.VersionName = e.Meta.VersionName
		meta.MinSDK = e.Meta.MinSDK
		meta.TargetSDK = e.Meta.TargetSDK
	}
	for ext := range e.DoNotCompress {
		meta.DoNotCompress = append(meta.DoNotCompress, ext)
	}
	sort.Strings(meta.DoNotCompress)
	meta.UnknownFiles = append([]string(nil), e.UnknownFiles...)
	sort.Strings(meta.UnknownFiles)

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(destDir, "omnisec-meta.json"), data, 0644)
}

// analyzeArtifacts walks the directory tree and runs heuristic scans
// on cache and patch files. Results go into e.Findings.
// All findings are indicators вЂ” binary files produce false positives.
// Manual triage is required before treating any finding as a verdict.
func (e *Extractor) analyzeArtifacts(root string) {
	auditCount := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			e.warn("artifact walk error at %s: %v", path, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}

		auditCount++
		if auditCount > maxAuditFiles {
			e.warn("artifact scan limit (%d files) reached вЂ” stopping early", maxAuditFiles)
			return filepath.SkipAll
		}

		lname := strings.ToLower(d.Name())

		isCacheArtifact := isCachePath(path) || isCacheExtension(lname)
		isPatch := strings.HasSuffix(lname, ".patch") || strings.HasSuffix(lname, ".diff")
		isOBB := strings.HasSuffix(lname, ".obb") || strings.HasSuffix(lname, ".unity3d") || strings.HasSuffix(lname, ".assetbundle")
		isJAR := isJavaArchiveName(lname)
		// Machine code must always reach the native scanner below: an .exe
		// (or .dll/.so/.elf) sitting in a plain zip otherwise walks past
		// with zero findings вЂ” exactly how a 34 MB dropper stub scored 0.
		isNative := isLikelyMachineCode(lname)

		if !isCacheArtifact && !isPatch && !isOBB && !isJAR && !isNative {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			e.warn("stat %s: %v", path, err)
			return nil
		}

		rel := strings.TrimPrefix(path, root)

		if isCacheArtifact && info.Size() > 50*1024*1024 {
			e.addFinding(path, types.SeverityMedium,
				fmt.Sprintf("cache artifact size anomaly: %d MB вЂ” possible embedded payload",
					info.Size()/1024/1024),
			)
		}

		if isJAR {
			e.analyzeJavaArchive(path)
		}

		if isOBB {
			res, err := obb.Scan(path)
			if err == nil && res != nil {
				e.warn("[obb] %s в†’ engine=%s bundles=%d payloads=%d urls=%d trackers=%d",
					rel, res.Engine, len(res.AssetBundles), len(res.HiddenPayloads),
					len(res.SuspiciousURLs), len(res.TrackerHints))
				for _, p := range res.HiddenPayloads {
					sev := types.SeverityMedium
					if p.Severity == "high" {
						sev = types.SeverityHigh
					}
					e.addFinding(path, sev, fmt.Sprintf("OBB hidden payload: %s (%s) вЂ” %s",
						p.Type, p.Path, p.Description))
				}
				for _, u := range res.SuspiciousURLs {
					e.addFinding(path, types.SeverityMedium,
						fmt.Sprintf("OBB URL: %s", u))
				}
				for _, t := range res.TrackerHints {
					e.addFinding(path, types.SeverityMedium,
						fmt.Sprintf("OBB tracker: %s", t))
				}
			}
			return nil
		}

		if isLikelyMachineCode(path) {
			e.addNativeSoPath(path)
			e.analyzeNativeSo(path)
		}

		hits := e.scanHeuristics(path, info.Size())
		for _, h := range hits {
			severity := types.SeverityMedium
			if isPatch {
				severity = types.SeverityHigh
			}
			e.addFinding(path, severity, h)
		}

		if len(hits) == 0 {
			e.warn("[artifact] %s (%.1f KB) вЂ” no suspicious patterns found",
				rel, float64(info.Size())/1024)
		}

		return nil
	})

	if err != nil {
		e.warn("analyzeArtifacts: walk error: %v", err)
	}
}

// scanHeuristics reads up to heuristicScanLimit bytes and searches for
// suspicious byte patterns. Returns human-readable reasons for each hit.
// Binary files will produce false positives вЂ” results are indicators only.
func (e *Extractor) scanHeuristics(path string, fileSize int64) []string {
	f, err := os.Open(path)
	if err != nil {
		e.warn("scanHeuristics open %s: %v", path, err)
		return nil
	}
	defer f.Close()

	// Clamp limit to actual file size to avoid over-allocation.
	limit := int64(heuristicScanLimit)
	if fileSize < limit {
		limit = fileSize
	}

	// Cast int64 в†’ int for make() вЂ” safe here because limit в‰¤ heuristicScanLimit = 4 MB.
	buf := make([]byte, int(limit))
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		e.warn("scanHeuristics read %s: %v", path, err)
		return nil
	}
	data := buf[:n]

	var hits []string
	for _, pattern := range suspiciousPatterns {
		if bytes.Contains(data, pattern) {
			hits = append(hits, fmt.Sprintf("pattern match: %q", pattern))
		}
	}

	// Structural heuristic: DEX magic inside a cache artifact that also
	// contains an exec() call is a strong code-injection indicator.
	// Still SUSPECT вЂ” not a verdict.
	if bytes.Contains(data, magicDEX) && bytes.Contains(data, []byte("exec(")) {
		hits = append(hits, "embedded DEX with exec() call вЂ” high-confidence injection indicator")
	}

	return hits
}

func isJavaArchiveName(path string) bool {
	lname := strings.ToLower(path)
	return strings.HasSuffix(lname, ".jar") || strings.HasSuffix(lname, ".war") || strings.HasSuffix(lname, ".ear") || strings.HasSuffix(lname, ".aar")
}

func (e *Extractor) analyzeJavaArchive(path string) {
	rep, err := jarloader.Analyze(path)
	if err != nil {
		e.warn("jar analysis failed for %s: %v", path, err)
		return
	}
	if !rep.Complete {
		e.warn("JAR inspection incomplete for %s: %d unreadable classes, %d recorded issues; %s", path, rep.UnparseableClasses, len(rep.InspectionIssues), rep.TruncateReason)
		for i, issue := range rep.InspectionIssues {
			if i >= 20 {
				break
			}
			e.warn("JAR inspection gap %s!/%s: %s", path, issue.Entry, issue.Reason)
		}
	}
	for _, f := range rep.Findings {
		reason := fmt.Sprintf("JAR finding: %s (%s)", f.Pattern, f.ReasonForSeverity)
		if f.Context != "" {
			reason += " вЂ” " + types.TruncateString(f.Context, 120)
		}
		evidence := f
		e.addFindings([]types.ArtifactFinding{{Path: path, Severity: f.Severity, Reason: reason, JVMEvidence: &evidence}})
		e.warn("[%s] %s вЂ” %s", f.Severity, filepath.Base(path), reason)
	}
	// Surface JAR crack points into the unified aggregation and as a compact
	// artifact finding so they show even if result.CrackPoint is never built.
	for _, cp := range rep.CrackPoints {
		e.addCrackPoint(cp)
		e.addFinding(path, crackPointSeverity(cp.Confidence),
			fmt.Sprintf("Crack point [%s]: %s (confidence %.2f) вЂ” %s",
				cp.Category, cp.Method, cp.Confidence, cp.Suggestion))
	}
	for _, dep := range rep.VulnDeps {
		sev := types.SeverityMedium
		switch strings.ToLower(dep.Severity) {
		case "critical":
			sev = types.SeverityCritical
		case "high":
			sev = types.SeverityHigh
		case "info":
			sev = types.SeverityInfo
		case "low":
			sev = types.SeverityLow
		}
		e.addFinding(path, sev, fmt.Sprintf("JAR vulnerable dependency: %s %s вЂ” %s", dep.Library, dep.CVE, dep.Summary))
	}
	// Surface declared mod-loader metadata as inventory: without this the
	// report shows JAR findings but never says WHAT mod the archive is.
	for _, mod := range rep.Mods {
		e.addFinding(path, types.SeverityInfo, describeJavaMod(mod))
	}
}

// describeJavaMod renders one mod-loader descriptor as a single inventory
// line (id, name, version, loader, game versions, authors, dep count) so the
// CLI report names the mod instead of only listing its bytecode findings.
func describeJavaMod(mod jarloader.JavaMod) string {
	var b strings.Builder
	id := mod.ID
	if id == "" {
		id = "unknown-id"
	}
	fmt.Fprintf(&b, "JAR mod metadata: %s", id)
	if mod.Name != "" && mod.Name != id {
		fmt.Fprintf(&b, " %q", mod.Name)
	}
	if mod.Version != "" {
		fmt.Fprintf(&b, " v%s", mod.Version)
	}
	if mod.Loader != "" {
		fmt.Fprintf(&b, " [%s]", mod.Loader)
	}
	if mod.GameVersion != "" {
		fmt.Fprintf(&b, " mc %s", mod.GameVersion)
	}
	authors := mod.Authors
	extra := ""
	if len(authors) > 3 {
		extra = fmt.Sprintf(" +%d more", len(authors)-3)
		authors = authors[:3]
	}
	if len(authors) > 0 {
		fmt.Fprintf(&b, " by %s%s", strings.Join(authors, ", "), extra)
	}
	if n := len(mod.Dependencies); n > 0 {
		word := "deps"
		if n == 1 {
			word = "dep"
		}
		fmt.Fprintf(&b, " вЂ” %d declared %s", n, word)
	}
	return b.String()
}

// maxNativeScanBytes caps a single machine-code input handed to the native
// (Rust/Go) scanners. ZIP entries up to 3 GB can claim a .so/.dll/.exe name;
// buffering one fully (twice, for base+Aetrium) used to be an easy OOM.
// 64 MiB covers all real-world .so files вЂ” anything larger is a red flag anyway.
const maxNativeScanBytes = 64 << 20

// maxCachedNativeFiles bounds the nativeData map: each entry can hold up to
// maxNativeScanBytes, so an APK with dozens of .so files must not pin them
// all. Files beyond the cap are re-read (capped) by the weaponization pass;
// the OS page cache makes that cheap.
const maxCachedNativeFiles = 8

// readNativeFile reads path, refusing to buffer anything above
// maxNativeScanBytes.
func readNativeFile(path string) ([]byte, error) {
	if info, err := os.Stat(path); err == nil && info.Size() > maxNativeScanBytes {
		return nil, fmt.Errorf("native file too large to scan: %d bytes (limit %d)", info.Size(), maxNativeScanBytes)
	}
	return os.ReadFile(path)
}

func (e *Extractor) analyzeNativeSo(path string) {
	data, err := readNativeFile(path)
	if err != nil {
		e.warn("failed to read .so file %s: %v", path, err)
		return
	}
	// Remember the bytes so the Aetrium weaponization pass reuses them
	// instead of reading (and scanning) the same file a second time.
	// The entry count is capped вЂ” see maxCachedNativeFiles вЂ” and
	// runWeaponization frees entries progressively, so a many-.so APK
	// cannot pin hundreds of MiB for the whole run.
	e.stateMu.Lock()
	if e.nativeData == nil {
		e.nativeData = make(map[string][]byte, 8)
	}
	if len(e.nativeData) < maxCachedNativeFiles {
		e.nativeData[path] = data
	}
	e.stateMu.Unlock()

	// We only do the BASE scan here.
	// ML-Aetrium/Apli-Ex is now a separate post-scan phase.
	report, err := ScanNativeWithRust(data)
	rustScanRan := err == nil && report != nil
	if err != nil || report == nil {
		// Rust scanner unavailable (not linked) or failed вЂ” fall back to the
		// pure-Go ELF/PE/Mach-O analyzer so machine-code analysis still works
		// on every build without a native toolchain.
		if goRep, ok := AnalyzeNativeGo(data); ok {
			report = goRep
		} else {
			if err != nil {
				e.warn("native scan unavailable for %s: %v", path, err)
			}
			return
		}
	} else if goRep, ok := AnalyzeNativeGo(data); ok {
		// Rust scan succeeded вЂ” corroborate and enrich it with the pure-Go
		// analyzer (entropy/packer detection, JNI surface, extra import/string
		// signals) so the machine-code verdict reflects both passes.
		enrichNativeReport(report, goRep)
	}

	// Add hardening findings
	if report.Hardening.NX != nil && !*report.Hardening.NX {
		e.addFinding(path, types.SeverityMedium, "Hardening: NX (No-Execute) is disabled")
	}
	if report.Hardening.PIE != nil && !*report.Hardening.PIE {
		e.addFinding(path, types.SeverityMedium, "Hardening: PIE (Position Independent Executable) is disabled")
	}
	if report.Hardening.Relro == "none" {
		e.addFinding(path, types.SeverityMedium, "Hardening: RELRO is disabled")
	}
	if report.Hardening.StackCanary != nil && !*report.Hardening.StackCanary {
		e.addFinding(path, types.SeverityMedium, "Hardening: Stack canary is missing")
	}

	// Add security findings
	for _, f := range report.Findings {
		severity := types.SeverityInfo
		switch f.Severity {
		case "medium":
			severity = types.SeverityMedium
		case "high", "critical":
			severity = types.SeverityHigh
		}

		reason := fmt.Sprintf("[%s] %s: %s (Evidence: %s)", f.Category, f.Title, f.Description, f.Evidence)
		finding := types.ArtifactFinding{
			Path:     path,
			Severity: severity,
			Reason:   reason,
		}
		if f.Payload != nil {
			finding.Payload = *f.Payload
		}
		e.addFindings([]types.ArtifactFinding{finding})
	}

	// Static dropper battery: import-set hash, embedded-payload sections,
	// unsigned overlay and the resource-extraction combo. Runs on the raw
	// bytes regardless of which native scanner produced the report above.
	for _, f := range DropperSignalsForPE(data) {
		severity := types.SeverityInfo
		switch f.Severity {
		case "medium":
			severity = types.SeverityMedium
		case "high", "critical":
			severity = types.SeverityHigh
		}
		e.addFindings([]types.ArtifactFinding{{
			Path:     path,
			Severity: severity,
			Reason:   fmt.Sprintf("[%s] %s: %s", f.Category, f.Title, f.Description),
		}})
	}

	// Native crack points + embedded secrets (pure-Go symbol/string scan вЂ” works
	// without the Rust bridge).
	for _, cp := range DetectNativeCrackPoints(data, path) {
		e.addCrackPoint(cp)
		e.addFindings([]types.ArtifactFinding{crackPointArtifact(cp, "native")})
	}
	// The APK-artifact extraction path has no CLI flag plumbed through it yet,
	// so it keeps the previous always-masked behavior. Numeric-PIN detection is
	// fallback-only вЂ” skip it when the Rust scan already covered the signal.
	e.addFindings(NativeSecretFindings(data, path, false, !rustScanRan))
}

// runWeaponization performs ML-Apli-Ex Phases 1-4 on high-confidence findings.
func (e *Extractor) runWeaponization(resultDir string) {
	// Resolve anchors through appconfig (env / exe dir / CWD fallback) instead
	// of a bare CWD-relative path that made behavior depend on launch dir.
	anchorPath := appconfig.Path("configs/aetrium_anchors.json")
	anchors, err := os.ReadFile(anchorPath)
	if err != nil {
		anchors, err = os.ReadFile(appconfig.Path("pkg/internal/configs/aetrium_anchors.json"))
	}
	if err != nil {
		// No on-disk file: fall back to the anchors baked into the binary.
		anchors = configs.AetriumAnchors()
	}
	if len(anchors) == 0 {
		return // No anchors, no Apli-Ex
	}

	// Look for machine-code files in the result directory and run the Aetrium pass
	for _, path := range e.NativeSoPaths {
		e.stateMu.Lock()
		data, cached := e.nativeData[path]
		e.stateMu.Unlock()
		if !cached {
			var err error
			data, err = readNativeFile(path)
			if err != nil {
				continue
			}
		}

		// Run the full 1-4 phase pipeline
		report, err := ScanNativeWithAetrium(data, anchors, true)
		if err != nil || report == nil {
			continue
		}

		for _, f := range report.Findings {
			if f.Category != "vulnerability" {
				continue
			}

			var severity types.Severity
			switch f.Severity {
			case "high", "critical":
				severity = types.SeverityHigh
			case "medium":
				severity = types.SeverityMedium
			default:
				severity = types.SeverityInfo
			}

			finding := types.ArtifactFinding{
				Path:     path,
				Severity: severity,
				Reason:   fmt.Sprintf("[ML-Apli-Ex] %s: %s", f.Title, f.Description),
				Stages:   f.Stages,
			}
			if f.Payload != nil {
				finding.Payload = *f.Payload
			}
			e.addFindings([]types.ArtifactFinding{finding})
		}
		// Free the retained bytes progressively; the map is dropped entirely
		// below so native payloads never outlive the weaponization pass.
		e.stateMu.Lock()
		delete(e.nativeData, path)
		e.stateMu.Unlock()
	}
	e.stateMu.Lock()
	e.nativeData = nil
	e.stateMu.Unlock()
}

// analyzePatch copies the patch to a temp dir and runs the full artifact
// analysis pass on it.
func (e *Extractor) analyzePatch(ctx context.Context, patchPath string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	tempDir, err := os.MkdirTemp(e.TempDir, "patch_audit_*")
	if err != nil {
		return "", &LoaderError{Op: "mkdir_temp", err: err}
	}

	dst := filepath.Join(tempDir, filepath.Base(patchPath))
	if err := copyFile(patchPath, dst); err != nil {
		os.RemoveAll(tempDir)
		return "", &LoaderError{Op: "analyze_patch", Path: patchPath, err: err}
	}

	e.analyzeArtifacts(tempDir)
	return tempDir, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		os.Remove(dst)
		return copyErr
	}
	return closeErr
}

func (e *Extractor) addFinding(path string, severity types.Severity, reason string) {
	e.addFindings([]types.ArtifactFinding{{
		Path:     path,
		Severity: severity,
		Reason:   reason,
	}})
	e.warn("[%s] %s вЂ” %s", severity, filepath.Base(path), reason)
}

// addFindings appends pre-built findings under stateMu. analyzeNativeSo and
// the parallel decode goroutines all funnel through the locked helpers below
// because two DecodeAPK/PrepareInput callers may share one Extractor.
func (e *Extractor) addFindings(fs []types.ArtifactFinding) {
	e.stateMu.Lock()
	e.Findings = append(e.Findings, fs...)
	e.stateMu.Unlock()
}

func (e *Extractor) addCrackPoint(cp types.CrackPoint) {
	e.stateMu.Lock()
	e.CrackPoints = append(e.CrackPoints, cp)
	e.stateMu.Unlock()
}

func (e *Extractor) addNativeSoPath(p string) {
	e.stateMu.Lock()
	e.NativeSoPaths = append(e.NativeSoPaths, p)
	e.stateMu.Unlock()
}

func (e *Extractor) setMeta(m *APKMeta) {
	e.stateMu.Lock()
	e.Meta = m
	e.stateMu.Unlock()
}

func (e *Extractor) findDEXFiles(dir string) []string {
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
	return dexFiles
}

func (e *Extractor) findAPKFiles(dir string) []string {
	var apkFiles []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".apk") {
			apkFiles = append(apkFiles, path)
		}
		return nil
	})
	return apkFiles
}

// supportedAnalysisExtensions вЂ” all artifact types worth preserving for analysis.
var supportedAnalysisExtensions = map[string]struct{}{
	".cfg": {}, ".conf": {}, ".env": {}, ".ini": {}, ".properties": {},
	".toml": {}, ".yaml": {}, ".yml": {},
	".java": {}, ".js": {}, ".json": {}, ".kt": {}, ".lua": {},
	".m": {}, ".mm": {}, ".mjs": {}, ".swift": {}, ".ts": {}, ".tsx": {},
	".htm": {}, ".html": {},
	".md": {}, ".txt": {},
	".mobileprovision": {}, ".plist": {}, ".strings": {},
	".sql":  {},
	".log":  {},
	".xml":  {},
	".vdex": {}, ".odex": {}, ".oat": {}, ".art": {}, ".prof": {},
	".patch": {}, ".diff": {},
}

var supportedAnalysisBasenames = map[string]struct{}{
	"androidmanifest.xml": {},
	"info.plist":          {},
}

func hasSupportedAnalysisFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found || d.IsDir() {
			return nil
		}
		lname := strings.ToLower(d.Name())
		if _, ok := supportedAnalysisBasenames[lname]; ok {
			found = true
			return filepath.SkipAll
		}
		ext := strings.ToLower(filepath.Ext(lname))
		if _, ok := supportedAnalysisExtensions[ext]; ok {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func (e *Extractor) decompileDEX(ctx context.Context, dexPath string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	tempDir, err := os.MkdirTemp(e.TempDir, "dex_analysis_*")
	if err != nil {
		return "", &LoaderError{Op: "mkdir_temp", err: err}
	}
	destination := filepath.Join(tempDir, filepath.Base(dexPath))
	if err := copyFile(dexPath, destination); err != nil {
		os.RemoveAll(tempDir)
		return "", &LoaderError{Op: "copy_dex", Path: dexPath, err: err}
	}
	e.ensurePlaceholderManifest(tempDir)
	return tempDir, nil
}

func (e *Extractor) generateSmaliFromDEX(parser *DEXParser, outputDir string) error {
	smaliDir := filepath.Join(outputDir, "smali")
	if err := e.generateSmaliIntoCached(context.Background(), parser, smaliDir, 0, true); err != nil {
		return err
	}
	e.ensurePlaceholderManifest(outputDir)
	return nil
}

func (e *Extractor) generateSmaliInto(parser *DEXParser, smaliDir string, workersCount int) error {
	return e.generateSmaliIntoCached(context.Background(), parser, smaliDir, workersCount, false)
}

func (e *Extractor) ensurePlaceholderManifest(outputDir string) {
	manifest := filepath.Join(outputDir, "AndroidManifest.xml")
	if _, err := os.Stat(manifest); os.IsNotExist(err) {
		placeholder := `<?xml version="1.0" encoding="utf-8"?>
<!-- Auto-generated placeholder -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
</manifest>`
		_ = os.WriteFile(manifest, []byte(placeholder), 0644)
	}
}

func (e *Extractor) warn(format string, args ...interface{}) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.Warnings = append(e.Warnings, fmt.Sprintf(format, args...))
}

func (e *Extractor) GetWarnings() []string                { return e.Warnings }
func (e *Extractor) GetFindings() []types.ArtifactFinding { return e.Findings }

// GetCrackPoints returns license/premium/tamper gates discovered in JAR and
// native artifacts during extraction (parallel to GetFindings).
func (e *Extractor) GetCrackPoints() []types.CrackPoint { return e.CrackPoints }

func (e *Extractor) Cleanup(tempDir string) error {
	if tempDir == "" {
		return nil
	}
	return os.RemoveAll(tempDir)
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// decodeAndSaveManifest reads a freshly-extracted AndroidManifest.xml,
// detects whether it's binary AXML, and if so writes a plaintext
// sibling so downstream stages have an inspectable manifest. The
// original binary file is preserved alongside as ".bin" for callers
// that need it.
//
// Behaviour matrix:
//   - already plaintext в†’ no-op, returns (nil, nil)
//   - binary, decoded   в†’ writes <path>.bin (original) and rewrites
//     <path> with the rendered XML
//   - binary, error     в†’ leaves original intact, returns the error
//
// The structured Manifest is also returned so the caller can log it
// or feed it into the privacy / threat pipelines without re-parsing.
func decodeAndSaveManifest(path string) (*axml.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if !axml.IsBinaryXML(data) {
		// Some apps ship plaintext manifests during dev builds; nothing
		// to decode.
		return nil, nil
	}

	manifest, err := axml.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	// Preserve the original binary chunk for tools that need it.
	binPath := path + ".bin"
	if err := os.WriteFile(binPath, data, 0644); err != nil {
		return manifest, fmt.Errorf("save .bin: %w", err)
	}

	if err := os.WriteFile(path, manifest.XMLBytes, 0644); err != nil {
		return manifest, fmt.Errorf("write decoded: %w", err)
	}

	return manifest, nil
}

// decodeAndSaveARSC parses resources.arsc and writes a JSON sidecar so
// downstream tools can operate on resolved strings without re-parsing
// the binary table. The original file is preserved untouched (callers
// rebuilding the APK still need the binary form).
//
// The sidecar lives next to the binary as `resources.arsc.json`. We
// write it as compact JSON because the typical table is hundreds of
// kilobytes; pretty-printing roughly doubles that for no gain.
func decodeAndSaveARSC(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	table, err := axml.ParseARSC(data)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// Also decode the manifest (if available next door) and resolve
	// its references against this table. This catches manifests that
	// were already extracted before the .arsc file in the zip walk.
	manifestPath := filepath.Join(filepath.Dir(path), "AndroidManifest.xml")
	if mdata, err := os.ReadFile(manifestPath); err == nil && axml.IsBinaryXML(mdata) {
		// Already-decoded text manifest produces IsBinaryXML=false, so
		// this branch only fires on the rare fallback where the
		// AXMLв†’XML pass hadn't run yet.
		if m, err := axml.Decode(mdata); err == nil {
			axml.ResolveManifest(m, table)
			_ = os.WriteFile(manifestPath, m.XMLBytes, 0644)
		}
	} else if err == nil {
		// Manifest already plaintext: rewrite @0x references inline.
		_ = os.WriteFile(manifestPath, []byte(axmlRewriteText(string(mdata), table)), 0644)
	}

	jsonBytes, err := encodeARSCJSON(table)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	// Export basic resources (strings, colors, dimens) to res/values/*.xml
	resDir := filepath.Join(filepath.Dir(path), "res")
	if err := axml.ExportTable(table, resDir); err != nil {
		return fmt.Errorf("export arsc to xml: %w", err)
	}

	return os.WriteFile(path+".json", jsonBytes, 0644)
}

// axmlRewriteText is a thin wrapper over the unexported rewrite helper
// in axml so we don't need to expose the regex internals.
func axmlRewriteText(xml string, table *axml.ResourceTable) string {
	// Apply via a temporary Manifest carrier so we reuse the same
	// rewrite path.
	m := &axml.Manifest{XMLBytes: []byte(xml)}
	axml.ResolveManifest(m, table)
	return string(m.XMLBytes)
}

func encodeARSCJSON(table *axml.ResourceTable) ([]byte, error) {
	return json.Marshal(table)
}

// isResourceXMLPath reports whether a zip entry name points at a
// binary XML resource that should be auto-decoded.
//
// We restrict the rewrite to paths under `res/` so we don't touch
// asset XMLs that authors deliberately ship as plaintext (e.g.
// network_security_config from `xml/` вЂ” already binary, but resource;
// vs HTML manifests under `assets/` вЂ” plaintext, must not be touched).
//
// AndroidManifest.xml is handled by its own branch upstream so it
// keeps the structured-decode side effects.
func isResourceXMLPath(zipPath string) bool {
	lower := strings.ToLower(zipPath)
	if !strings.HasSuffix(lower, ".xml") {
		return false
	}
	if strings.EqualFold(filepath.Base(zipPath), "AndroidManifest.xml") {
		return false
	}
	// Both forward and back slashes appear in well-formed APKs, but
	// the zip standard uses forward slashes; we still tolerate either.
	normalized := strings.ReplaceAll(lower, "\\", "/")
	return strings.HasPrefix(normalized, "res/")
}

// decodeAndSaveAXML attempts to interpret the file at `path` as binary
// AXML. On success, the file is rewritten in place with the rendered
// XML text. On failure (unparseable or already plaintext) the file is
// left as-is вЂ” this keeps the operation idempotent and safe to retry.
func decodeAndSaveAXML(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if !axml.IsBinaryXML(data) {
		// Already plaintext or not an XML chunk at all; nothing to do.
		return nil
	}
	rendered, err := axml.Render(data)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}
	binPath := path + ".bin"
	_ = os.WriteFile(binPath, data, 0644)
	return os.WriteFile(path, []byte(rendered), 0644)
}

func isLikelyMachineCode(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".so", ".dll", ".exe", ".elf", ".dylib", ".bin", ".o", ".a", ".sys":
		return true
	}
	return false
}

func sanitizeWindowsPath(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	normalized := strings.ReplaceAll(path, "\\", "/")
	segments := strings.Split(normalized, "/")
	for i, seg := range segments {
		segments[i] = sanitizeReservedWindowsName(seg)
	}
	return strings.Join(segments, string(os.PathSeparator))
}

func sanitizeReservedWindowsName(name string) string {
	if runtime.GOOS != "windows" {
		return name
	}
	ext := filepath.Ext(name)
	baseNoExt := strings.TrimSuffix(name, ext)
	upper := strings.ToUpper(baseNoExt)

	switch upper {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return "_" + baseNoExt + ext
	}
	return name
}
