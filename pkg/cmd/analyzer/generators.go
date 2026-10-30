package main

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/report"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT GENERATORS
// ═══════════════════════════════════════════════════════════════════════════════

type generatorEntry struct {
	name string
	gen  func(outputDir string) error
}

type GeneratorRegistry struct {
	result     *types.AnalysisResult
	mdOpts     report.MarkdownOptions
	artifacts  *report.ArtifactsView
	generators []generatorEntry
}

func NewGeneratorRegistry(result *types.AnalysisResult, mdOpts report.MarkdownOptions) *GeneratorRegistry {
	r := &GeneratorRegistry{
		result: result,
		mdOpts: mdOpts,
	}
	r.rebuildGenerators()
	return r
}

// WithArtifacts attaches an opt-in Artifacts view to the JSON / HTML
// generators. nil keeps the section out of the output.
func (r *GeneratorRegistry) WithArtifacts(view *report.ArtifactsView) *GeneratorRegistry {
	r.artifacts = view
	r.rebuildGenerators()
	return r
}

func (r *GeneratorRegistry) rebuildGenerators() {
	result := r.result
	mdOpts := r.mdOpts
	artifacts := r.artifacts
	r.generators = []generatorEntry{
		{
			name: "Markdown report",
			gen: func(outputDir string) error {
				return report.NewMarkdownReporter(result).WithOptions(mdOpts).Generate(outputDir)
			},
		},
		{
			name: "JSON report",
			gen: func(outputDir string) error {
				return report.NewJSONReporter(result).WithArtifacts(artifacts).Generate(outputDir)
			},
		},
		{
			name: "HTML report",
			gen: func(outputDir string) error {
				return report.NewHTMLReporter(result).WithMarkdownOptions(mdOpts).WithArtifacts(artifacts).Generate(outputDir)
			},
		},
	}
}

func (r *GeneratorRegistry) DisableHTML() {
	kept := r.generators[:0]
	for _, g := range r.generators {
		if g.name == "HTML report" {
			continue
		}
		kept = append(kept, g)
	}
	r.generators = kept
}

func (r *GeneratorRegistry) DisableJSON() {
	kept := r.generators[:0]
	for _, g := range r.generators {
		if g.name == "JSON report" {
			continue
		}
		kept = append(kept, g)
	}
	r.generators = kept
}

func (r *GeneratorRegistry) GenerateAll(outputDir string, output *Output) error {
	var failures []string

	for _, g := range r.generators {
		if err := g.gen(outputDir); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", g.name, err))
			if output != nil {
				output.Warning("Failed to generate %s: %v", g.name, err)
			}
			continue
		}

		if output != nil {
			output.Success("%s generated", g.name)
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}

	return nil
}
