package main

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestModuleResultViewIsolatesFindingsAndSharesReadOnlyInputs(t *testing.T) {
	files := map[string]*types.FileAnalysis{"a": {Path: "a.smali"}}
	source := &types.AnalysisResult{
		AppPackage:       "com.example.app",
		Files:            files,
		ArtifactFindings: []types.ArtifactFinding{{Path: "main", Reason: "existing"}},
	}
	local := moduleResultView(source)
	if local.AppPackage != source.AppPackage || local.Files["a"] != source.Files["a"] {
		t.Fatal("module view should share immutable analysis inputs")
	}
	if len(local.ArtifactFindings) != 0 {
		t.Fatal("module view must start with an isolated findings slice")
	}
	local.ArtifactFindings = append(local.ArtifactFindings, types.ArtifactFinding{Path: "sidecar", Reason: "new"})
	if len(source.ArtifactFindings) != 1 || source.ArtifactFindings[0].Path != "main" {
		t.Fatal("sidecar append mutated main result before merge")
	}
}
