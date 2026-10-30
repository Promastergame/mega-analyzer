package smaliaudit

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/ml"
)

// Main returns 0 for a completed static audit, 2 for incomplete coverage and
// 1 for invocation/I/O failures. Findings do NOT automatically mean malware.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("smali-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "APK, DEX, smali file, or smali directory (read-only)")
	output := flags.String("json", "smali-audit.json", "JSON report destination")
	sarif := flags.String("sarif", "", "Optional SARIF 2.1.0 destination")
	workers := flags.Int("workers", 0, "Signal worker count; default GOMAXPROCS, max 64")
	timeout := flags.Duration("timeout", 2*time.Minute, "Cooperative total analysis deadline")
	maxMethods := flags.Int("max-methods", 100000, "Maximum methods retained")
	maxFindings := flags.Int("max-findings", 2000, "Maximum ranked findings")
	maxSliceSteps := flags.Int("max-slice-steps", 500000, "Maximum backward slice states across the run")
	packageName := flags.String("package", "", "App package override for smali-only input")
	flowOnly := flags.Bool("flow-only", false, "Omit method-level heuristics from findings")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	if *input == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Usage: smali-audit -input app.apk -json audit.json [-sarif audit.sarif]")
		return 1
	}
	if *timeout <= 0 || *maxMethods <= 0 || *maxFindings <= 0 || *maxSliceSteps <= 0 || *workers < 0 {
		fmt.Fprintln(stderr, "Budgets must be positive; workers may be zero for auto.")
		return 1
	}
	if *output == "" {
		fmt.Fprintln(stderr, "A JSON output path is required.")
		return 1
	}
	if err := validateOutputPaths(*input, *output, *sarif); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	cfg := ml.SmaliAuditConfig{Workers: *workers, Timeout: *timeout, MaxMethods: *maxMethods, MaxFindings: *maxFindings, MaxSliceSteps: *maxSliceSteps, AppPackage: *packageName, NoHeuristics: *flowOnly}
	report, err := Run(ctx, Options{Input: *input, Config: cfg})
	if err != nil {
		fmt.Fprintln(stderr, "Audit failed:", err)
		return 1
	}
	if err := WriteJSON(*output, report); err != nil {
		fmt.Fprintln(stderr, "Report write failed:", err)
		return 1
	}
	if *sarif != "" {
		if err := WriteJSON(*sarif, SARIF(report)); err != nil {
			fmt.Fprintln(stderr, "SARIF write failed:", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "%s: %d methods, %d static-flow candidates, %d heuristic signals; %d ranked findings.\n", report.Audit.Verdict, report.Audit.Coverage.MethodsAnalyzed, report.Audit.Coverage.StaticFlows, report.Audit.Coverage.SignalsDetected, len(report.Audit.Findings))
	fmt.Fprintf(stdout, "JSON: %s\n", *output)
	if !report.Audit.AnalysisComplete {
		return 2
	}
	return 0
}

func validateOutputPaths(input string, outputs ...string) error {
	in, err := filepath.Abs(input)
	if err != nil {
		return err
	}
	in, err = filepath.EvalSymlinks(in)
	if err != nil {
		return err
	}
	info, err := os.Stat(in)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, output := range outputs {
		if output == "" {
			continue
		}
		out, err := filepath.Abs(output)
		if err != nil {
			return err
		}
		out, err = resolvedOutputPath(out)
		if err != nil {
			return err
		}
		if out == in {
			return fmt.Errorf("report must not overwrite the input")
		}
		if info.IsDir() {
			rel, e := filepath.Rel(in, out)
			if e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("report destinations must be outside the input directory")
			}
		}
		if other, e := os.Stat(out); e == nil && os.SameFile(info, other) {
			return fmt.Errorf("report destination aliases the input")
		}
		if seen[out] {
			return fmt.Errorf("JSON and SARIF destinations must differ")
		}
		seen[out] = true
	}
	return nil
}

// Resolve existing ancestors too: an output parent symlink must not turn an
// apparently external report destination into a write inside the input tree.
func resolvedOutputPath(filename string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(filename); err == nil {
		return resolved, nil
	}
	parent := filepath.Dir(filename)
	if parent == filename {
		return filename, nil
	}
	resolved, err := resolvedOutputPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(filename)), nil
}
