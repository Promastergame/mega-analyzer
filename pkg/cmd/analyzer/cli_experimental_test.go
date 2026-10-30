package main

import (
	"strings"
	"testing"
)

func TestCLIParser_AEGFlag(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--aeg", "-t", "."})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.AEG {
		t.Fatal("expected AEG=true after Parse")
	}
	// MLEx is enabled by Validate() (so the experimental subsystem auto-runs).
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !opts.MLEx {
		t.Fatal("expected MLEx=true after Validate (implied by --aeg)")
	}
}

func TestCLIParser_AEGFlag_ValidationDefaultsSelector(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--aeg", "-t", "."})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !strings.Contains(strings.ToLower(opts.MLExApply), "aeg") {
		t.Fatalf("expected selector to include 'aeg', got %q", opts.MLExApply)
	}
}

func TestCLIParser_MLExApply(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--ml-ex-apply", "1-4", "-t", "."})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if opts.MLExApply != "1-4" {
		t.Fatalf("MLExApply = %q, want %q", opts.MLExApply, "1-4")
	}
	if !opts.MLEx {
		t.Fatal("expected MLEx auto-enabled by --ml-ex-apply")
	}
}

func TestCLIParser_MLExDefault_AllSelector(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--ml-ex", "-t", "."})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if opts.MLExApply != "all" {
		t.Fatalf("expected default selector 'all', got %q", opts.MLExApply)
	}
}

func TestCLIParser_MLExList_NoTargetRequired(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--ml-ex-list"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !opts.IsMLCommand() {
		t.Fatal("expected --ml-ex-list to be detected as ML command")
	}
}

func TestCLIParser_MLExTimeoutNegative(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--ml-ex", "--ml-ex-timeout", "-1", "-t", "."})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected validation to reject negative timeout")
	}
}

func TestCLIParser_AEGCombinedSelector(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"--aeg", "--ml-ex-apply", "macho,binsim", "-t", "."})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !strings.Contains(opts.MLExApply, "aeg") {
		t.Fatalf("expected selector to include 'aeg' after --aeg, got %q", opts.MLExApply)
	}
	if !strings.Contains(opts.MLExApply, "macho") || !strings.Contains(opts.MLExApply, "binsim") {
		t.Fatalf("expected selector to retain user picks, got %q", opts.MLExApply)
	}
}
