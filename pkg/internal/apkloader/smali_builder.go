package apkloader

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sync"
	"path/filepath"
	"strings"
	"time"
)

// SmaliToolConfig holds paths to external smali/baksmali jars.
// These are optional — when absent the rebuilder skips smali→dex
// and falls back to Hyperion direct DEX patching (already in-memory).
type SmaliToolConfig struct {
	SmaliJar             string // path to smali.jar (smali → dex assembler)
	BaksmaliJar          string // path to baksmali.jar (dex → smali disassembler)
	JavaBinary           string // "java" or full path
	APILevel             int    // smali/baksmali -a/--api; 0 = auto from tree dex version
	JavaHeapMB           int    // -Xmx for the assembler JVM; 0 = tool default
	Jobs                 int    // smali/baksmali -j/--jobs; 0 auto-limits per process
	Verbose              bool   // smali --verbose for richer diagnostics
	UseLocals            bool   // baksmali --use-locals
	SequentialLabels     bool   // baksmali --sequential-labels
	NoParameterRegisters bool   // baksmali --parameter-registers=false
}

// dexVersionAPI maps a dex file version to the smali --api level that
// reproduces it (measured against smali 2.5.2):
//
//	035 (tool default) <- api 15
//	038 <- api 26-27
//	039 <- api 28+
//
// smali 2.5.2 cannot emit 037 at all. Rebuilding a 037 tree without --api
// silently downgrades every dex to 035, and ART then throws
// IncompatibleClassChangeError on interface-heavy code (Jetpack Compose);
// mixing rebuilt-035 with untouched-037 dex in one APK guarantees it.
func dexVersionAPI(magic []byte) int {
	if len(magic) < 8 || string(magic[:4]) != "dex\n" {
		return 0
	}
	switch string(magic[4:7]) {
	case "037":
		return 28 // closest smali can emit (039); keeps one uniform version
	case "038":
		return 26
	case "039":
		return 28
	}
	return 0 // 035 and unknown: tool default
}

// DetectTreeAPILevel scans classes*.dex in sourceDir and returns the smali
// --api level matching the newest dex version found, or 0 when every dex is
// 035/unknown (tool default is then correct).
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

// DefaultSmaliConfig tries to auto-detect smali tools in common locations.
func DefaultSmaliConfig() SmaliToolConfig {
	cfg := SmaliToolConfig{}
	if Standalone() {
		return cfg
	}
	cfg.SmaliJar, _ = LocateSmaliJar()
	cfg.BaksmaliJar, _ = LocateBaksmaliJar()
	cfg.JavaBinary, _ = LocateJava()
	return cfg
}

// BuildDEXFromSmali invokes smali.jar to assemble .smali files into a .dex.
// It walks sourceDir for smali/ and smali_*/ subdirectories (Apktool layout).
//
// Returns a slice of (outputDexPath, error) pairs — one per smali dir.
// If SmaliJar or JavaBinary is missing, returns ErrSmaliToolNotFound.
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

func BuildDEXFromSmali(sourceDir string, cfg SmaliToolConfig) ([]string, error) {
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
// (or resources-only edited) project needs no smali/baksmali/Java at all.
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

func BuildDEXFromSmaliContextWithWarnings(ctx context.Context, sourceDir string, cfg SmaliToolConfig, opts SmaliBuildOptions) ([]string, []string, error) {
	jobs, err := listSmaliJobs(sourceDir)
	if err != nil {
		return nil, nil, err
	}
	if len(jobs) == 0 {
		return nil, nil, fmt.Errorf("no smali directories found in %s", sourceDir)
	}

	workers := opts.MaxWorkers
	if workers <= 0 {
		workers = runtime.NumCPU() / 2
	}
	if workers < 1 { workers = 1 }
	if workers > 4 { workers = 4 }
	if workers > len(jobs) { workers = len(jobs) }

	var dexPaths []string
	var warnings []string
	var errs []string

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
	// Native Go assembly first: no JVM, no smali.jar. Only trees with
	// constructs the native writer cannot represent fall through to Java.
	nativeBuilt, javaJobs, nativeErrs, nativeWarns := tryNativeAssembleJobs(jobs, cfg.APILevel)
	warnings = append(warnings, nativeWarns...)
	errs = append(errs, nativeErrs...)
	for _, job := range nativeBuilt {
		dexPaths = append(dexPaths, job.dexPath)
		if opts.Incremental {
			if h, herr := hashSmaliDir(job.dir); herr == nil {
				cache.Entries[job.name] = SmaliBuildCacheEntry{Hash: h, DexPath: relDexPath(sourceDir, job.dexPath), Tool: "native"}
			}
		}
	}
	jobs = javaJobs
	if len(jobs) == 0 {
		if len(errs) > 0 {
			return nil, warnings, fmt.Errorf("smali build errors: %s", strings.Join(errs, "; "))
		}
		if opts.Incremental {
			saveSmaliBuildCache(sourceDir, cache)
		}
		return dexPaths, warnings, nil
	}
	// Only now do we need the external assembler: unchanged directories were
	// served from the snapshot/cache above and representable trees natively.
	if Standalone() {
		if len(errs) > 0 {
			return nil, warnings, fmt.Errorf("smali build errors: %s", strings.Join(errs, "; "))
		}
		return nil, warnings, fmt.Errorf("%s", StandaloneReason("smali.jar"))
	}
	if cfg.SmaliJar == "" || cfg.JavaBinary == "" {
		if len(errs) > 0 {
			return nil, warnings, fmt.Errorf("smali build errors: %s", strings.Join(errs, "; "))
		}
		return nil, warnings, ErrSmaliToolNotFound
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
				out, err := assembleOneSmaliDir(ctx, cfg, job)
				var builtHash string
				if err == nil && opts.Incremental {
					builtHash, _ = hashSmaliDir(job.dir)
				}
				mu.Lock()
				if err != nil {
					errs = append(errs, err.Error())
					if opts.FailFast { cancel() }
				} else {
					dexPaths = append(dexPaths, out)
					if opts.Incremental && builtHash != "" {
						cache.Entries[job.name] = SmaliBuildCacheEntry{Hash: builtHash, DexPath: relDexPath(sourceDir, job.dexPath), Tool: cfg.SmaliJar}
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
	// The caller falls back to the original decoded dex files instead, keeping
	// the APK internally consistent.
	if len(errs) > 0 {
		return nil, warnings, fmt.Errorf("smali build errors: %s", strings.Join(errs, "; "))
	}
	if opts.Incremental {
		saveSmaliBuildCache(sourceDir, cache)
	}
	return dexPaths, warnings, nil
}

// BuildDEXFromSmaliContext assembles smali directories into DEX files,
// preferring the native Go assembler and falling back to smali.jar.
func BuildDEXFromSmaliContext(ctx context.Context, sourceDir string, cfg SmaliToolConfig, opts SmaliBuildOptions) ([]string, error) {
	paths, _, err := BuildDEXFromSmaliContextWithWarnings(ctx, sourceDir, cfg, opts)
	return paths, err
}

func assembleOneSmaliDir(ctx context.Context, cfg SmaliToolConfig, job smaliDirJob) (string, error) {
	javaArgs := []string{}
	if cfg.JavaHeapMB > 0 {
		javaArgs = append(javaArgs, fmt.Sprintf("-Xmx%dm", cfg.JavaHeapMB))
	}
	args := append(javaArgs, jarInvocation(cfg.SmaliJar, smaliMainClass)...)
	args = append(args, "assemble", "-o", job.dexPath)
	if cfg.APILevel > 0 {
		args = append(args, "-a", fmt.Sprintf("%d", cfg.APILevel))
	}
	jobs := cfg.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	if jobs < 1 {
		jobs = 1
	}
	if jobs > 8 {
		jobs = 8
	}
	args = append(args, "-j", fmt.Sprintf("%d", jobs))
	if cfg.Verbose {
		args = append(args, "--verbose")
	}
	args = append(args, job.dir)
	cmd := exec.CommandContext(ctx, cfg.JavaBinary, args...)
	var before time.Time
	if fi, statErr := os.Stat(job.dexPath); statErr == nil { before = fi.ModTime() }
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		diags := ParseSmaliToolOutput("smali_assemble", job.name, trimmed)
		if len(diags) > 0 { return "", fmt.Errorf("%s: %v diagnostics=%s", job.name, err, diagnosticsJSON(diags)) }
		return "", fmt.Errorf("%s: %v (output: %s)", job.name, err, trimmed)
	}
	fi, statErr := os.Stat(job.dexPath)
	if statErr != nil || before.Equal(fi.ModTime()) {
		return "", fmt.Errorf("%s: assembler exited 0 but did not rewrite the dex (output: %s)", job.name, trimmed)
	}
	return job.dexPath, nil
}

var smaliLocRe = regexp.MustCompile(`(?m)([^\s:]+\.smali)(?::|\[)(\d+)?(?:,|:)?(\d+)?`)

func ParseSmaliToolOutput(stage, fallbackPath, output string) []Diagnostic {
	if strings.TrimSpace(output) == "" { return nil }
	m := smaliLocRe.FindStringSubmatch(output)
	d := Diagnostic{Code:"SMALI_TOOL_ERROR", Severity:DiagError, Stage:stage, Path:fallbackPath, Message:firstNonEmptyLine(output), Cause:output, Hint:"open the referenced .smali file and fix the syntax/register error reported by smali"}
	if len(m) > 0 {
		d.Path = m[1]
		if m[2] != "" { fmt.Sscanf(m[2], "%d", &d.Line) }
		if m[3] != "" { fmt.Sscanf(m[3], "%d", &d.Column) }
	}
	return []Diagnostic{d}
}

func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") { if strings.TrimSpace(l) != "" { return strings.TrimSpace(l) } }
	return strings.TrimSpace(s)
}

// DisassembleDEXToSmali invokes baksmali.jar to disassemble a .dex file into .smali files.
func DisassembleDEXToSmali(dexPath string, outputDir string, cfg SmaliToolConfig) error {
	return DisassembleDEXToSmaliContext(context.Background(), dexPath, outputDir, cfg)
}

// DisassembleDEXToSmaliContext invokes baksmali with cancellation support.
func DisassembleDEXToSmaliContext(ctx context.Context, dexPath string, outputDir string, cfg SmaliToolConfig) error {
	if cfg.BaksmaliJar == "" || cfg.JavaBinary == "" {
		return ErrSmaliToolNotFound
	}

	args := append(jarInvocation(cfg.BaksmaliJar, baksmaliMain), "disassemble", dexPath, "-o", outputDir)
	if cfg.APILevel > 0 {
		args = append(args, "-a", fmt.Sprintf("%d", cfg.APILevel))
	}
	jobs := cfg.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	if jobs < 1 {
		jobs = 1
	}
	if jobs > 8 {
		jobs = 8
	}
	args = append(args, "-j", fmt.Sprintf("%d", jobs))
	if cfg.UseLocals {
		args = append(args, "--use-locals")
	}
	if cfg.SequentialLabels {
		args = append(args, "--sequential-labels")
	}
	if cfg.NoParameterRegisters {
		args = append(args, "--parameter-registers=false")
	}
	cmd := exec.CommandContext(ctx, cfg.JavaBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return diagnosticsError("baksmali_disassemble", ParseSmaliToolOutput("baksmali_disassemble", dexPath, strings.TrimSpace(string(output))))
	}
	return nil
}

// ErrSmaliToolNotFound is returned when smali.jar or java is missing.
var ErrSmaliToolNotFound = fmt.Errorf("smali.jar or java not found; install smali tools or use Hyperion direct DEX patching")

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
