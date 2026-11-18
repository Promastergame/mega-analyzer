//go:build cgo && omnisec_ml_gnn

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestGNNDiagnosticsRetainsNegativeClassAndOpaqueBodyCoverage(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	weights, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "gnn", "integration-weights.json"))
	if err != nil {
		t.Fatal(err)
	}
	var model map[string]any
	if err := json.Unmarshal(weights, &model); err != nil {
		t.Fatal(err)
	}
	head := model["classifier_weights"].([]any)
	for i := range head {
		head[i] = 0.0
	}
	bias := model["classifier_bias"].([]any)
	for i := range bias {
		bias[i] = 0.0
	}
	bias[0] = 8.0
	weights, err = json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "negative.json")
	if err := os.WriteFile(path, weights, 0600); err != nil {
		t.Fatal(err)
	}
	result := types.NewAnalysisResult("fixture")
	result.Files = map[string]*types.FileAnalysis{"A.smali": {Path: "A.smali", RelPath: "A.smali", SmaliClass: &types.SmaliClass{
		Name: "test.A", Methods: []types.SmaliMethod{
			{Name: "run", ReturnType: "V", Body: []string{"const/4 v0, 0", "if-eqz v0, :end", "return-void", ":end", "return-void"}},
			{Name: "hidden", ReturnType: "V", Access: types.AccessNative, Body: []string{".method native hidden()V", "# opaque", ".end method"}},
		},
	}}}
	app := &App{opts: &CLIOptions{Workers: 2}, output: NewOutputWithWriter(DarkTheme(), true, &bytes.Buffer{})}
	if err := app.runGNNClassification(context.Background(), result, path); err != nil {
		t.Fatal(err)
	}
	d := result.GNNDiagnostics
	if d == nil || d.Status != "complete" || d.MethodsDiscovered != 2 || d.MethodsInferred != 1 || d.MethodsSkipped != 1 ||
		d.MethodsNotProcessed != 0 || d.PredictionsByClass["benign"] != 1 || len(result.GNNFindings) != 0 || len(d.Model.SHA256) != 64 {
		t.Fatalf("negative prediction or opaque-body coverage lost: %+v", d)
	}
	for _, method := range d.Methods {
		if method.Status == "predicted" && (len(method.ClassProbabilities) != 8 || method.Outcome != "negative_taxonomy_class") {
			t.Fatalf("incomplete negative prediction: %+v", method)
		}
	}
}

func TestGNNModelValidationFailureDoesNotRetainOldFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	result := types.NewAnalysisResult("fixture")
	result.GNNFindings = []types.GNNFinding{{Method: "stale", VulnClass: "dynamic-load"}}
	result.Files = map[string]*types.FileAnalysis{"A.smali": {SmaliClass: &types.SmaliClass{Name: "A",
		Methods: []types.SmaliMethod{{Name: "run", ReturnType: "V", Body: []string{"const/4 v0, 0", "return-void", ".end method"}}}}}}
	app := &App{opts: &CLIOptions{Workers: 1}, output: NewOutputWithWriter(DarkTheme(), true, &bytes.Buffer{})}
	if err := app.runGNNClassification(context.Background(), result, path); err == nil {
		t.Fatal("invalid model accepted")
	}
	if len(result.GNNFindings) != 0 || result.GNNDiagnostics.Status != "unavailable" ||
		result.GNNDiagnostics.MethodsNotProcessed != 1 || result.GNNDiagnostics.Error == "" {
		t.Fatalf("model failure hidden: %+v", result.GNNDiagnostics)
	}
}
