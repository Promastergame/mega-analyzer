package main

import (
	"bytes"
	"testing"

	"mega-analyzer/pkg/internal/report"
	"mega-analyzer/pkg/internal/types"
)

func makeResult() *types.AnalysisResult {
	return types.NewAnalysisResult("/tmp/test.apk")
}

func TestNewGeneratorRegistry_NotNil(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	if r == nil {
		t.Fatal("expected non-nil GeneratorRegistry")
	}
}

func TestGeneratorRegistry_WithArtifacts(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	r2 := r.WithArtifacts(nil)
	if r2 == nil {
		t.Fatal("WithArtifacts should return self")
	}
}

func TestGeneratorRegistry_DisableHTML(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	initialCount := len(r.generators)
	r.DisableHTML()
	if len(r.generators) != initialCount-1 {
		t.Errorf("DisableHTML should remove 1 generator, got %d remaining (was %d)", len(r.generators), initialCount)
	}
	for _, g := range r.generators {
		if g.name == "HTML report" {
			t.Error("HTML report should be removed after DisableHTML")
		}
	}
}

func TestGeneratorRegistry_DisableJSON(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	initialCount := len(r.generators)
	r.DisableJSON()
	if len(r.generators) != initialCount-1 {
		t.Errorf("DisableJSON should remove 1 generator")
	}
	for _, g := range r.generators {
		if g.name == "JSON report" {
			t.Error("JSON report should be removed after DisableJSON")
		}
	}
}

func TestGeneratorRegistry_GenerateAll_NoDir(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	buf := &bytes.Buffer{}
	o := NewOutputWithWriter(NoColorTheme(), false, buf)
	// Generate into a temp dir
	dir := t.TempDir()
	err := r.GenerateAll(dir, o)
	if err != nil {
		t.Errorf("GenerateAll: %v", err)
	}
}

func TestGeneratorRegistry_GenerateAll_WithOutput(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	buf := &bytes.Buffer{}
	o := NewOutputWithWriter(NoColorTheme(), false, buf)
	r.DisableHTML()
	dir := t.TempDir()
	r.GenerateAll(dir, o)
	_ = buf.String()
}

func TestGeneratorRegistry_GenerateAll_NilOutput(t *testing.T) {
	r := NewGeneratorRegistry(makeResult(), report.MarkdownOptions{})
	dir := t.TempDir()
	// nil output should not panic
	r.GenerateAll(dir, nil)
}

func TestCLIOptions_IsFuzzCommand(t *testing.T) {
	opts := &CLIOptions{Fuzz: true}
	if !opts.IsFuzzCommand() {
		t.Error("expected IsFuzzCommand() = true when Fuzz=true")
	}
	opts2 := &CLIOptions{Fuzz: false}
	if opts2.IsFuzzCommand() {
		t.Error("expected IsFuzzCommand() = false when Fuzz=false")
	}
}

func TestNormalizeResolution(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1080x1920", "1080x1920"},
		{"720p", "720x1280"},
		{"1080p", "1080x1920"},
		{"2k", "1440x2560"},
		{"", ""},
		{"notaresolution", ""},
		{"100x100", ""}, // below 240 threshold
		{"500x600", "500x600"},
	}
	for _, c := range cases {
		got := normalizeResolution(c.in)
		if got != c.want {
			t.Errorf("normalizeResolution(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
