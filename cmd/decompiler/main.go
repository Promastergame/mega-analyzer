// Command decompiler decodes APK/ZIP bundles and standalone DEX files.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/decompiler"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decompiler", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts decompiler.Options
	var backend string
	var jsonOutput, version bool
	var timeout time.Duration
	fs.StringVar(&opts.OutputDir, "o", "", "Output directory (default decoded_<name>)")
	fs.StringVar(&opts.OutputDir, "output", "", "Output directory")
	fs.StringVar(&backend, "backend", "native", "Decode backend: native, auto")
	fs.BoolVar(&opts.Standalone, "standalone", false, "Forbid external tools for this invocation")
	fs.BoolVar(&opts.NoResources, "no-resources", false, "Keep Android resources in their original binary form")
	fs.BoolVar(&opts.NoSmali, "no-smali", false, "Keep DEX files without generating Smali")
	fs.BoolVar(&opts.Headers, "headers", false, "Include source/hash comments in native Smali")
	fs.BoolVar(&opts.JavaView, "java-view", false, "Emit per-class .java pseudocode next to smali")
	fs.BoolVar(&opts.ClassCache, "class-cache", true, "Cache native Smali generation")
	fs.BoolVar(&opts.CopyOriginal, "copy-original", false, "Preserve META-INF in original/ for rebuilding")
	fs.DurationVar(&timeout, "timeout", 0, "Time limit, e.g. 30s or 2m (0 = unlimited)")
	fs.BoolVar(&jsonOutput, "json", false, "Write one JSON result to stdout, including failures")
	fs.BoolVar(&version, "version", false, "Print version")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: decompiler <app.apk|bundle.zip|classes.dex> [options]")
		fmt.Fprintln(stderr, "Native decoding requires no Java or Android SDK.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(interspersedArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if version {
		fmt.Fprintf(stdout, "decompiler %s\n", buildinfo.Version)
		return 0
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "Exactly one input file is required.")
		fs.Usage()
		return 2
	}
	if timeout < 0 {
		fmt.Fprintln(stderr, "Timeout must be non-negative.")
		return 2
	}
	opts.Backend = decompiler.Backend(backend)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	result, err := decompiler.Decode(ctx, fs.Arg(0), opts)
	if jsonOutput {
		report := struct {
			decompiler.Result
			Error string `json:"error,omitempty"`
		}{Result: result}
		if err != nil {
			report.Error = err.Error()
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if writeErr := enc.Encode(report); writeErr != nil {
			fmt.Fprintf(stderr, "write JSON result: %v\n", writeErr)
			return 1
		}
	} else {
		for _, warning := range result.Warnings {
			fmt.Fprintln(stderr, warning)
		}
		if err == nil {
			fmt.Fprintf(stdout, "Decoded %s\nOutput: %s\nBackend: %s; DEX files: %d; Smali files: %d\n",
				result.Input, result.OutputDir, result.Backend, result.DEXFiles, result.SmaliFiles)
		} else {
			fmt.Fprintf(stderr, "Decode failed: %v\n", err)
			if result.OutputDir != "" {
				fmt.Fprintf(stderr, "Partial output: %s\n", result.OutputDir)
			}
		}
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if err != nil {
		return 1
	}
	return 0
}
