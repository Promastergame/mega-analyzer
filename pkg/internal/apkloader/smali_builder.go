package apkloader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// SmaliBuildConfig configures the native Go Smali→DEX assembler.
type SmaliBuildConfig struct {
	APILevel int // Android API level; 0 = auto from the project DEX version
	Jobs     int // concurrent DEX assembly jobs; 0 = automatic, capped at four
}

// dexVersionAPI selects an Android API level that keeps the rebuilt DEX
// version compatible with the project. A 037 tree is emitted as 039 by the
// current native writer; 038 and 039 map to API 26 and 28 respectively.
func dexVersionAPI(magic []byte) int {
	if len(magic) < 8 || string(magic[:4]) != "dex\n" {
		return 0
	}
	switch string(magic[4:7]) {
	case "037":
		return 28 // native writer emits 039; keeps one uniform version
	case "038":
		return 26
	case "039":
		return 28
	}
	return 0 // 035 and unknown: native default
}

// DetectTreeAPILevel scans classes*.dex in sourceDir and returns the Android
// API level matching the newest dex version found, or 0 when every dex is
// 035/unknown (the native default is then correct).
func DetectTreeAPILevel(sourceDir string) int {
	best := 0
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return 0
	}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".dex") {
			continue
		}
		f, err := os.Open(filepath.Join(sourceDir, name))
		if err != nil {
			continue
		}
		magic := make([]byte, 8)
		_, rerr := io.ReadFull(f, magic)
		f.Close()
		if rerr != nil {
			continue
		}
		if api := dexVersionAPI(magic); api > best {
			best = api
		}
	}
	return best
}

type SmaliBuildOptions struct {
	MaxWorkers       int
	StrictValidation bool
	Incremental      bool
	FailFast         bool
}

type smaliDirJob struct {
	name    string
	dir     string
	dexPath string
}

func BuildDEXFromSmali(sourceDir string, cfg SmaliBuildConfig) ([]string, error) {
	return BuildDEXFromSmaliContext(context.Background(), sourceDir, cfg, SmaliBuildOptions{})
}

// listSmaliJobs maps every smali/ and smali_*/ directory to the dex it produces.
func listSmaliJobs(sourceDir string) ([]smaliDirJob, error) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("read source dir: %w", err)
	}
	var jobs []smaliDirJob
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name != "smali" && !strings.HasPrefix(name, "smali_") {
			continue
		}
		dexName := "classes.dex"
		if name != "smali" {
			suffix := strings.TrimPrefix(name, "smali_")
			suffix = strings.ReplaceAll(suffix, "@", string(filepath.Separator))
			dexName = suffix + ".dex"
		}
		jobs = append(jobs, smaliDirJob{name: name, dir: filepath.Join(sourceDir, name), dexPath: filepath.Join(sourceDir, dexName)})
	}
	return jobs, nil
}

// RecordSmaliSnapshot remembers the content hash of every freshly decoded
// smali directory next to the dex it came from. A later build that finds the
// smali tree byte-identical can reuse that dex as-is, so building an unedited
// (or resources-only edited) project needs no assembly at all.
func RecordSmaliSnapshot(sourceDir string) {
	jobs, err := listSmaliJobs(sourceDir)
	if err != nil || len(jobs) == 0 {
		return
	}
	cache := loadSmaliBuildCache(sourceDir)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, job := range jobs {
		if _, err := os.Stat(job.dexPath); err != nil {
			continue
		}
		wg.Add(1)
		go func(job smaliDirJob) {
			defer wg.Done()
			h, err := hashSmaliDir(job.dir)
			if err != nil {
				return
			}
			mu.Lock()
			cache.Entries[job.name] = SmaliBuildCacheEntry{Hash: h, DexPath: relDexPath(sourceDir, job.dexPath), Tool: "decode-snapshot"}
			mu.Unlock()
		}(job)
	}
	wg.Wait()
	saveSmaliBuildCache(sourceDir, cache)
}

// SmaliTreeChanged compares every smali directory with the snapshot taken at
// decode/last build time. changed = snapshot exists and the content differs (a
// definite edit); unknown = no usable snapshot, so nothing can be proven.
func SmaliTreeChanged(sourceDir string) (changed, unknown []string, err error) {
	jobs, err := listSmaliJobs(sourceDir)
	if err != nil {
		return nil, nil, err
	}
	cache := loadSmaliBuildCache(sourceDir)
	for _, job := range jobs {
		entry, ok := cache.Entries[job.name]
		if !ok {
			unknown = append(unknown, job.name)
			continue
		}
		if _, statErr := os.Stat(job.dexPath); statErr != nil {
			unknown = append(unknown, job.name)
			continue
		}
		h, herr := hashSmaliDir(job.dir)
		if herr != nil || h != entry.Hash || !sameDexPath(sourceDir, entry.DexPath, job.dexPath) {
			changed = append(changed, job.name)
		}
	}
	return changed, unknown, nil
}

func BuildDEXFromSmaliContextWithWarnings(ctx context.Context, sourceDir string, cfg SmaliBuildConfig, opts SmaliBuildOptions) ([]string, []string, error) {
	jobs, err := listSmaliJobs(sourceDir)
	if err != nil {
		return nil, nil, err
	}
	if len(jobs) == 0 {
		return nil, nil, fmt.Errorf("no smali directories found in %s", sourceDir)
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	workers := opts.MaxWorkers
	if cfg.Jobs > 0 {
		workers = cfg.Jobs
	}
	if workers <= 0 {
		workers = runtime.NumCPU() / 2
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 4 {
		workers = 4
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}

	var dexPaths []string
	var warnings []string
	var errs []error

	cache := loadSmaliBuildCache(sourceDir)
	if opts.Incremental {
		kept := jobs[:0]
		for _, job := range jobs {
			hash, err := hashSmaliDir(job.dir)
			entry := cache.Entries[job.name]
			if err == nil && entry.Hash == hash && sameDexPath(sourceDir, entry.DexPath, job.dexPath) {
				if _, statErr := os.Stat(job.dexPath); statErr == nil {
					dexPaths = append(dexPaths, job.dexPath)
					continue
				}
			}
			kept = append(kept, job)
		}
		jobs = kept
	}
	if len(jobs) == 0 {
		return dexPaths, warnings, nil
	}
	jobCh := make(chan smaliDirJob, len(jobs))
	for _, job := range jobs {
		jobCh <- job
	}
	close(jobCh)

	var wg sync.WaitGroup
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if ctx.Err() != nil {
					return
				}
				out, notes, err := assembleOneSmaliDir(ctx, cfg, job)
				var builtHash string
				if err == nil && opts.Incremental {
					builtHash, _ = hashSmaliDir(job.dir)
				}
				mu.Lock()
				warnings = append(warnings, notes...)
				if err != nil {
					errs = append(errs, err)
					if opts.FailFast {
						cancel()
					}
				} else {
					dexPaths = append(dexPaths, out)
					if opts.Incremental && builtHash != "" {
						cache.Entries[job.name] = SmaliBuildCacheEntry{Hash: builtHash, DexPath: relDexPath(sourceDir, job.dexPath), Tool: "native"}
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil && len(errs) == 0 {
		return nil, warnings, ctx.Err()
	}
	// On any failure return no dex paths at all: a partial list would make the
	// rebuilder package a mix of stale decoded dex and fresh assembled dex.
	// The caller reports the failure and does not publish an APK.
	if len(errs) > 0 {
		return nil, warnings, fmt.Errorf("smali build errors: %w", errors.Join(append(errs, ctx.Err())...))
	}
	if opts.Incremental {
		saveSmaliBuildCache(sourceDir, cache)
	}
	sort.Strings(dexPaths)
	sort.Strings(warnings)
	return dexPaths, warnings, nil
}

// BuildDEXFromSmaliContext assembles smali directories into DEX files,
// using only the native Go assembler.
func BuildDEXFromSmaliContext(ctx context.Context, sourceDir string, cfg SmaliBuildConfig, opts SmaliBuildOptions) ([]string, error) {
	paths, _, err := BuildDEXFromSmaliContextWithWarnings(ctx, sourceDir, cfg, opts)
	return paths, err
}

func assembleOneSmaliDir(ctx context.Context, cfg SmaliBuildConfig, job smaliDirJob) (string, []string, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	dex, warnings, err := AssembleSmaliDirNative(job.dir, cfg.APILevel)
	if err != nil {
		return "", warnings, fmt.Errorf("%s: %w", job.name, err)
	}
	if err := ctx.Err(); err != nil {
		return "", warnings, err
	}
	if err := os.WriteFile(job.dexPath, dex, 0o644); err != nil {
		return "", warnings, err
	}
	return job.dexPath, warnings, nil
}

func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(s)
}

// relDexPath stores the dex location relative to the project so the snapshot
// survives moving or renaming the decoded directory.
func relDexPath(sourceDir, dexPath string) string {
	if rel, err := filepath.Rel(sourceDir, dexPath); err == nil {
		return filepath.ToSlash(rel)
	}
	return dexPath
}

func sameDexPath(sourceDir, recorded, actual string) bool {
	return recorded == actual || recorded == relDexPath(sourceDir, actual)
}
