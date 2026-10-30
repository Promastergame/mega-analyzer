package main

import "testing"

func TestCLIArtifactsFlags(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"-t", "./app",
		"--artifacts",
		"--allow-export",
		"--artifacts-max-mb", "5",
		"--artifacts-budget", "50",
		"--no-image-blur",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !opts.EnableArtifacts {
		t.Error("EnableArtifacts should be true")
	}
	if !opts.AllowExport {
		t.Error("AllowExport should be true")
	}
	if opts.ArtifactsMaxMB != 5 {
		t.Errorf("ArtifactsMaxMB = %d, want 5", opts.ArtifactsMaxMB)
	}
	if opts.ArtifactsBudgetMB != 50 {
		t.Errorf("ArtifactsBudgetMB = %d, want 50", opts.ArtifactsBudgetMB)
	}
	if !opts.NoImageBlur {
		t.Error("NoImageBlur should be true")
	}
}

func TestCLIArtifactsDefaultOff(t *testing.T) {
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{"-t", "./app"})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if opts.EnableArtifacts {
		t.Error("EnableArtifacts should default to false")
	}
	if opts.AllowExport {
		t.Error("AllowExport should default to false")
	}
}

func TestCLIArtifactsValidationDefaults(t *testing.T) {
	// Sub-flags without --artifacts: should silently force defaults so
	// the off-path stays zero-impact.
	parser := NewCLIParser()
	opts, err := parser.Parse([]string{
		"-t", "./app",
		"--allow-export",
		"--no-image-blur",
	})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if opts.AllowExport {
		t.Error("AllowExport should be reset when --artifacts is off")
	}
	if opts.NoImageBlur {
		t.Error("NoImageBlur should be reset when --artifacts is off")
	}
}
