package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractComplete(t *testing.T) {
	dir := t.TempDir()

	// 1. Create a few .version files to trigger getGroupName and version prefix rules
	os.WriteFile(filepath.Join(dir, "androidx-fragment_1.3.6.version"), []byte("1.3.6"), 0644)
	os.WriteFile(filepath.Join(dir, "kotlinx-coroutines.version"), []byte("1.5.2"), 0644)
	os.WriteFile(filepath.Join(dir, "com.example_lib.version"), []byte("2.0.0"), 0644)
	// Version starting with "task" -> should become "dynamic"
	os.WriteFile(filepath.Join(dir, "task-based-lib.version"), []byte("task-generated-v1"), 0644)
	os.WriteFile(filepath.Join(dir, "gson.version"), []byte("2.8.9"), 0644)
	os.WriteFile(filepath.Join(dir, "okhttp.version"), []byte("4.9.3"), 0644)
	os.WriteFile(filepath.Join(dir, "retrofit.version"), []byte("2.9.0"), 0644)

	// 2. Create a synthetic go.mod file
	goModContent := `
		module example.com/app

		go 1.20

		require (
			github.com/google/uuid v1.3.0
			github.com/jackson/json v2.12.3 // indirect
			// This is a comment
			github.com/log4j/core v2.17.1
		)
	`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goModContent), 0644)

	// 3. Extract Report
	rep, err := Extract(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Verify deps count
	if rep.Count == 0 {
		t.Fatal("Expected dependencies to be found")
	}

	// Find specific dependencies and verify their properties
	foundUUID := false
	foundJackson := false
	foundTask := false

	for _, d := range rep.Deps {
		if d.Name == "github.com/google/uuid" && d.Group == "go" && d.Version == "v1.3.0" {
			foundUUID = true
		}
		if d.Name == "github.com/jackson/json" && d.Group == "go" && d.Version == "v2.12.3" {
			foundJackson = true
		}
		if d.Name == "task-based-lib" && d.Version == "dynamic" {
			foundTask = true
		}
	}

	if !foundUUID {
		t.Error("Expected go.mod dependency 'github.com/google/uuid' to be extracted")
	}
	if !foundJackson {
		t.Error("Expected go.mod indirect dependency 'github.com/jackson/json' to be extracted")
	}
	if !foundTask {
		t.Error("Expected version string starting with 'task' to be normalized to 'dynamic'")
	}

	if rep.Verdict != "inventory" || rep.Score != 0 {
		t.Errorf("Inventory must not infer a vulnerability from count or module names: %+v", rep)
	}

	// 4. Verify ExportSPDX
	spdx := ExportSPDX(rep)
	if !strings.Contains(spdx, "SPDXVersion: SPDX-2.3") || !strings.Contains(spdx, "PackageName: kotlinx-coroutines") {
		t.Error("ExportSPDX generated invalid document")
	}

	// 5. Verify RenderMarkdown
	md := rep.RenderMarkdown()
	if !strings.Contains(md, "# SBOM Report") || !strings.Contains(md, "| Group | Name | Version | Raw |") {
		t.Error("RenderMarkdown generated invalid document")
	}
}

func TestInventoryVerdicts(t *testing.T) {
	// Test verdict ok (0 < score < 30)

	// We run it through Extract on empty dir or custom score report
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "clean-lib.version"), []byte("1.0.0"), 0644)
	repA, _ := Extract(dir)
	if repA.Verdict != "inventory" {
		t.Errorf("Expected verdict 'inventory', got %s", repA.Verdict)
	}

	// Test verdict clean (0 deps)
	dirEmpty := t.TempDir()
	repEmpty, _ := Extract(dirEmpty)
	if repEmpty.Verdict != "no_components_identified" || repEmpty.Count != 0 {
		t.Errorf("Expected 'no_components_identified' and count 0, got %s, %d", repEmpty.Verdict, repEmpty.Count)
	}
	mdEmpty := repEmpty.RenderMarkdown()
	if !strings.Contains(mdEmpty, "No supported dependency metadata identified.") {
		t.Error("Expected markdown to show no files found warning")
	}
}
