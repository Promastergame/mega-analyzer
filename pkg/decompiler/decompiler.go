// Package decompiler provides APK and DEX decoding without running a security
// scan. The native backend works without Java or the Android SDK.
//
// Each Decode call owns its loader and options. Calls may run concurrently when
// they use different output directories. Parser and resource implementations are
// shared with the analyzer; consumers do not need to import internal packages.
package decompiler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/apkloader"
)

type Backend string

const (
	BackendAuto     Backend = "auto" // resolves to native, regardless of installed tools
	BackendNative   Backend = "native"
	BackendBaksmali Backend = "baksmali"
)

// BaksmaliOptions applies only to an explicitly selected baksmali backend.
// Empty paths enable discovery for that backend. Native decoding never
// discovers, unpacks or launches external tools.
type BaksmaliOptions struct {
	JarPath              string
	JavaPath             string
	APILevel             int
	Jobs                 int
	JavaHeapMB           int
	UseLocals            bool
	SequentialLabels     bool
	NoParameterRegisters bool
}

type Options struct {
	// OutputDir defaults to decoded_<input basename> in the working directory.
	// Use a dedicated directory: generated files may be replaced on a repeat
	// decode. Do not use a project containing edits that need to be preserved.
	OutputDir    string
	Backend      Backend
	Standalone   bool // forbid external tools for this call; never changes global policy
	NoResources  bool
	NoSmali      bool
	Headers      bool // include source/hash comments in native Smali
	JavaView     bool // emit per-class .java pseudocode next to smali
	ClassCache   bool
	CopyOriginal bool
	FrameworkDir string
	Baksmali     BaksmaliOptions
}

// Result is also the JSON contract used by the standalone command.
// A non-nil error means Complete is false. OutputDir and Warnings remain
// available for inspecting a partial decode; they do not imply success.
type Result struct {
	Input      string   `json:"input"`
	OutputDir  string   `json:"output_dir"`
	Backend    Backend  `json:"backend"`
	Complete   bool     `json:"complete"`
	DEXFiles   int      `json:"dex_files"`
	SmaliFiles int      `json:"smali_files"`
	Warnings   []string `json:"warnings,omitempty"`
}

func Decode(ctx context.Context, input string, opts Options) (Result, error) {
	result := Result{Backend: opts.Backend}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if strings.TrimSpace(input) == "" {
		return result, fmt.Errorf("a path to an APK, ZIP bundle or DEX is required")
	}
	absInput, err := filepath.Abs(input)
	if err != nil {
		return result, fmt.Errorf("input path: %w", err)
	}
	result.Input = absInput
	info, err := os.Stat(absInput)
	if err != nil {
		return result, fmt.Errorf("input file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("decode input must be a regular APK, ZIP or DEX file: %s", absInput)
	}
	inputType, err := apkloader.DetectInputType(absInput)
	if err != nil {
		return result, err
	}
	if inputType != apkloader.InputTypeAPKFile && inputType != apkloader.InputTypeArchiveFile && inputType != apkloader.InputTypeDEXFile {
		return result, fmt.Errorf("unsupported decode input: %s", absInput)
	}
	switch opts.Backend {
	case "", BackendAuto, BackendNative:
		result.Backend = BackendNative
	case BackendBaksmali:
		if opts.Standalone || apkloader.Standalone() {
			return result, fmt.Errorf("standalone mode forbids the baksmali backend; use native")
		}
	default:
		return result, fmt.Errorf("invalid backend %q: use auto, native or baksmali", opts.Backend)
	}
	output := opts.OutputDir
	if output == "" {
		output = "decoded_" + strings.TrimSuffix(filepath.Base(absInput), filepath.Ext(absInput))
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return result, fmt.Errorf("output path: %w", err)
	}
	if rel, err := filepath.Rel(absOutput, absInput); err == nil && filepath.IsLocal(rel) {
		return result, fmt.Errorf("output directory must not contain the input file")
	}

	var cfg apkloader.SmaliToolConfig
	if result.Backend == BackendBaksmali && !opts.NoSmali {
		cfg = apkloader.DefaultSmaliConfig()
		if opts.Baksmali.JarPath != "" {
			cfg.BaksmaliJar = opts.Baksmali.JarPath
		}
		if opts.Baksmali.JavaPath != "" {
			cfg.JavaBinary = opts.Baksmali.JavaPath
		}
		cfg.APILevel = opts.Baksmali.APILevel
		cfg.Jobs = opts.Baksmali.Jobs
		cfg.JavaHeapMB = opts.Baksmali.JavaHeapMB
		cfg.UseLocals = opts.Baksmali.UseLocals
		cfg.SequentialLabels = opts.Baksmali.SequentialLabels
		cfg.NoParameterRegisters = opts.Baksmali.NoParameterRegisters
	}
	decodeOpts := apkloader.DecodeOptions{
		OutputDir: absOutput, NoResources: opts.NoResources, NoSmali: opts.NoSmali,
		SmaliHeaders: opts.Headers, Standalone: opts.Standalone,
		FrameworkDir: opts.FrameworkDir, CopyOriginal: opts.CopyOriginal,
		SmaliCfg: cfg, DexBackend: apkloader.DecompileBackend(result.Backend), ClassCache: opts.ClassCache,
		JavaView: opts.JavaView,
	}
	loader := apkloader.NewExtractor()
	var decodeErr error
	if inputType == apkloader.InputTypeDEXFile {
		result.OutputDir, decodeErr = loader.DecodeDEX(ctx, absInput, decodeOpts)
	} else {
		result.OutputDir, decodeErr = loader.DecodeAPK(ctx, absInput, decodeOpts)
	}
	result.Warnings = append([]string(nil), loader.GetWarnings()...)
	sort.Strings(result.Warnings)
	if result.OutputDir != "" && decodeErr == nil {
		decodeErr = countArtifacts(ctx, &result)
	}
	decodeErr = errors.Join(decodeErr, ctx.Err())
	result.Complete = decodeErr == nil
	return result, decodeErr
}

func countArtifacts(ctx context.Context, result *Result) error {
	return filepath.WalkDir(result.OutputDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".smali":
			result.SmaliFiles++
		case ".dex":
			result.DEXFiles++
		}
		return nil
	})
}
