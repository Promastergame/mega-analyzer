package main

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/internal/verdict"
)

func TestExitCodesFlagsParse(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"-exit-codes", "-fail-on", "high", "./app"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.ExitCodes || opts.FailOn != "high" {
		t.Fatalf("flags not parsed: %+v", opts)
	}
	opts, err = NewCLIParser().Parse([]string{"./app"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ExitCodes || opts.FailOn != "critical" {
		t.Fatalf("defaults must keep legacy behaviour (exit codes off): %+v", opts)
	}
}

func TestFailOnIsValidated(t *testing.T) {
	opts := &CLIOptions{FailOn: "banana"}
	if err := opts.Validate(); err == nil {
		t.Fatal("invalid -fail-on must be rejected")
	}
}

func TestAssessExitOffByDefault(t *testing.T) {
	verdict.ResetDegradations()
	a := &App{opts: &CLIOptions{}}
	res := &types.AnalysisResult{}
	res.Stats.CriticalMatches = 3
	a.assessExit(res)
	if a.ExitCode() != 0 {
		t.Fatalf("exit code must stay 0 without -exit-codes, got %d", a.ExitCode())
	}
}

func TestAssessExitMapsVerdict(t *testing.T) {
	verdict.ResetDegradations()
	t.Cleanup(verdict.ResetDegradations)

	a := &App{opts: &CLIOptions{ExitCodes: true, FailOn: "critical"}}
	res := &types.AnalysisResult{}
	res.Stats.TotalFiles, res.Stats.AnalyzedFiles = 4, 4
	a.assessExit(res)
	if a.ExitCode() != 0 {
		t.Fatalf("clean scan: got %d", a.ExitCode())
	}

	res.Coverage.ParseFailed = 1
	a.assessExit(res)
	if a.ExitCode() != 4 {
		t.Fatalf("incomplete scan: got %d", a.ExitCode())
	}

	res.Stats.CriticalMatches = 1
	a.assessExit(res)
	if a.ExitCode() != 1 {
		t.Fatalf("critical finding must win over incomplete: got %d", a.ExitCode())
	}
}
