package main

import (
	"testing"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/config"
)

// ─── splitArgs ────────────────────────────────────────────────────────────────

func TestSplitArgs_Simple(t *testing.T) {
	args, err := splitArgs("--foo bar --baz")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 3 || args[0] != "--foo" || args[1] != "bar" || args[2] != "--baz" {
		t.Errorf("got %v", args)
	}
}

func TestSplitArgs_DoubleQuotes(t *testing.T) {
	args, err := splitArgs(`--output "path with spaces"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[1] != "path with spaces" {
		t.Errorf("got %v", args)
	}
}

func TestSplitArgs_SingleQuotes(t *testing.T) {
	args, err := splitArgs(`--name 'hello world'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[1] != "hello world" {
		t.Errorf("got %v", args)
	}
}

func TestSplitArgs_UnclosedDoubleQuote(t *testing.T) {
	_, err := splitArgs(`--foo "unclosed`)
	if err == nil {
		t.Error("expected error for unclosed double quote")
	}
}

func TestSplitArgs_UnclosedSingleQuote(t *testing.T) {
	_, err := splitArgs(`--foo 'unclosed`)
	if err == nil {
		t.Error("expected error for unclosed single quote")
	}
}

func TestSplitArgs_Empty(t *testing.T) {
	args, err := splitArgs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 {
		t.Errorf("expected empty, got %v", args)
	}
}

func TestSplitArgs_TabSeparated(t *testing.T) {
	args, err := splitArgs("--foo\t--bar")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %v", args)
	}
}

// ─── parseFlagsFile ───────────────────────────────────────────────────────────

func TestParseFlagsFile_CommentsSkipped(t *testing.T) {
	content := "# this is a comment\n// also a comment\n--foo bar\n"
	args, err := parseFlagsFile(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0] != "--foo" {
		t.Errorf("got %v", args)
	}
}

func TestParseFlagsFile_EmptyLines(t *testing.T) {
	content := "\n\n--foo\n\n--bar\n"
	args, err := parseFlagsFile(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 {
		t.Errorf("expected 2, got %v", args)
	}
}

func TestParseFlagsFile_UnclosedQuote(t *testing.T) {
	_, err := parseFlagsFile(`--foo "unclosed`)
	if err == nil {
		t.Error("expected error")
	}
}

// ─── applyEnvDefaults ─────────────────────────────────────────────────────────

func TestApplyEnvDefaults_Output(t *testing.T) {
	t.Setenv(config.EnvOutputDir, "/tmp/testout")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if opts.Output != "/tmp/testout" {
		t.Errorf("Output not set from env: %q", opts.Output)
	}
}

func TestApplyEnvDefaults_Workers(t *testing.T) {
	t.Setenv(config.EnvWorkers, "7")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if opts.Workers != 7 {
		t.Errorf("Workers not set: %d", opts.Workers)
	}
}

func TestApplyEnvDefaults_WorkersInvalid(t *testing.T) {
	t.Setenv(config.EnvWorkers, "notanumber")
	p := NewCLIParser()
	opts := &CLIOptions{Workers: 4}
	p.applyEnvDefaults(opts)
	if opts.Workers != 4 {
		t.Errorf("invalid Workers should not override: %d", opts.Workers)
	}
}

func TestApplyEnvDefaults_Timeout(t *testing.T) {
	t.Setenv(config.EnvTimeout, "120")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if opts.Timeout != 120 {
		t.Errorf("Timeout: %d", opts.Timeout)
	}
}

func TestApplyEnvDefaults_Debug(t *testing.T) {
	t.Setenv(config.EnvDebug, "1")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if !opts.DebugVerbose {
		t.Error("DebugVerbose should be true")
	}
}

func TestApplyEnvDefaults_DebugFalse(t *testing.T) {
	t.Setenv(config.EnvDebug, "false")
	p := NewCLIParser()
	opts := &CLIOptions{DebugVerbose: true}
	p.applyEnvDefaults(opts)
	if opts.DebugVerbose {
		t.Error("DebugVerbose should be false")
	}
}

func TestApplyEnvDefaults_Quiet(t *testing.T) {
	t.Setenv(config.EnvQuiet, "yes")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if !opts.Quiet {
		t.Error("Quiet should be true")
	}
}

func TestApplyEnvDefaults_NoColor(t *testing.T) {
	t.Setenv(config.EnvNoColor, "on")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if !opts.NoColor {
		t.Error("NoColor should be true")
	}
}

func TestApplyEnvDefaults_MaxFiles(t *testing.T) {
	t.Setenv(config.EnvMaxFiles, "500")
	p := NewCLIParser()
	opts := &CLIOptions{}
	p.applyEnvDefaults(opts)
	if opts.MaxFiles != 500 {
		t.Errorf("MaxFiles: %d", opts.MaxFiles)
	}
}

// ─── IsLikelyMachineCodeTarget ────────────────────────────────────────────────

func TestIsLikelyMachineCodeTarget_So(t *testing.T) {
	if !IsLikelyMachineCodeTarget("libnative.so") {
		t.Error(".so should be machine code target")
	}
}

func TestIsLikelyMachineCodeTarget_DLL(t *testing.T) {
	if !IsLikelyMachineCodeTarget("module.dll") {
		t.Error(".dll should be machine code target")
	}
}

func TestIsLikelyMachineCodeTarget_EXE(t *testing.T) {
	if !IsLikelyMachineCodeTarget("app.exe") {
		t.Error(".exe should be machine code target")
	}
}

func TestIsLikelyMachineCodeTarget_APK(t *testing.T) {
	if IsLikelyMachineCodeTarget("app.apk") {
		t.Error(".apk should NOT be machine code target")
	}
}

func TestIsLikelyMachineCodeTarget_Empty(t *testing.T) {
	if IsLikelyMachineCodeTarget("") {
		t.Error("empty should NOT be machine code target")
	}
}

// ─── computeMachineCodeStats ──────────────────────────────────────────────────

func TestComputeMachineCodeStats_Nil(t *testing.T) {
	stats := computeMachineCodeStats(nil)
	if stats.TotalFindings != 0 {
		t.Errorf("nil scan should have 0 findings: %d", stats.TotalFindings)
	}
}

func strPtr(s string) *string { return &s }

func TestComputeMachineCodeStats_WithFindings(t *testing.T) {
	cwe := "CWE-123"
	payload := "shellcode"
	scan := &apkloader.NativeScanReport{
		Findings: []apkloader.NativeFinding{
			{Severity: "high", Category: "memory", CWE: &cwe, Payload: &payload},
			{Severity: "high", Category: "crypto"},
			{Severity: "low", Category: "memory"},
		},
	}
	stats := computeMachineCodeStats(scan)
	if stats.TotalFindings != 3 {
		t.Errorf("TotalFindings: %d", stats.TotalFindings)
	}
	if stats.BySeverity["high"] != 2 {
		t.Errorf("BySeverity[high]: %d", stats.BySeverity["high"])
	}
	if stats.ByCategory["memory"] != 2 {
		t.Errorf("ByCategory[memory]: %d", stats.ByCategory["memory"])
	}
	if stats.WithCWE != 1 {
		t.Errorf("WithCWE: %d", stats.WithCWE)
	}
	if stats.WeaponizedPayloads != 1 {
		t.Errorf("WeaponizedPayloads: %d", stats.WeaponizedPayloads)
	}
}

func TestComputeMachineCodeStats_EmptyFindings(t *testing.T) {
	scan := &apkloader.NativeScanReport{Findings: nil}
	stats := computeMachineCodeStats(scan)
	if stats.TotalFindings != 0 {
		t.Errorf("empty findings: %d", stats.TotalFindings)
	}
}

func TestComputeMachineCodeStats_EmptyCWEAndPayload(t *testing.T) {
	emptyCWE := ""
	emptyPayload := ""
	scan := &apkloader.NativeScanReport{
		Findings: []apkloader.NativeFinding{
			{Severity: "medium", CWE: &emptyCWE, Payload: &emptyPayload},
		},
	}
	stats := computeMachineCodeStats(scan)
	if stats.WithCWE != 0 {
		t.Errorf("empty CWE ptr should not count: %d", stats.WithCWE)
	}
	if stats.WeaponizedPayloads != 0 {
		t.Errorf("empty payload ptr should not count: %d", stats.WeaponizedPayloads)
	}
}
