//go:build cgo && omnisec_ml_gnn

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

// Fixed synthetic weights test the ABI and report wiring, not model accuracy.
func TestGNNIntegrationFixedWeights(t *testing.T) {
	src := `.class public Ltest/License;
.super Ljava/lang/Object;
.method public check(I)I
 .locals 1
 if-eqz p1, :denied
 const/4 v0, 0x1
 return v0
 :denied
 const/4 v0, 0x0
 return v0
.end method
`
	class, err := parser.NewSmaliParser(src).Parse()
	if err != nil {
		t.Fatal(err)
	}
	// The pipeline normally slices method bodies out of the file text;
	// a bare Parse leaves Body empty and the stage would see no methods.
	lines := strings.Split(src, "\n")
	for i := range class.Methods {
		m := &class.Methods[i]
		if m.LineStart > 0 && m.LineEnd <= len(lines) {
			m.Body = lines[m.LineStart-1 : m.LineEnd]
		}
	}
 app := &App{opts: &CLIOptions{Workers: 1}, output: NewOutputWithWriter(DarkTheme(), true, &bytes.Buffer{})}
 model := filepath.Join("..", "..", "..", "testdata", "gnn", "integration-weights.json")
 result := &types.AnalysisResult{Files: map[string]*types.FileAnalysis{"License.smali": {Path:"License.smali", RelPath:"License.smali", SmaliClass:class}}}
	if err := app.runGNNClassification(context.Background(), result, model); err != nil {
		t.Fatal(err)
	}
	if len(result.GNNFindings) != 1 {
		t.Fatalf("expected inference in report, got %+v", result.GNNFindings)
	}
	finding := result.GNNFindings[0]
	// Wiring assertions only: the class must be right and the confidence
	// must clear the production quality gate (gnnMinConfidence). Pinning an
	// exact high confidence here would couple the test to trainer
	// overfitting dynamics instead of the ABI it guards.
	if finding.VulnClass != "license-bypass" || finding.Confidence < gnnMinConfidence || finding.Method == "" {
		t.Fatalf("unexpected prediction: %+v", finding)
	}
 encoded, err := json.Marshal(result)
 if err != nil { t.Fatal(err) }
 var decoded types.AnalysisResult
 if err := json.Unmarshal(encoded,&decoded); err != nil { t.Fatal(err) }
 if len(decoded.GNNFindings)!=1 || decoded.GNNFindings[0].VulnClass!=finding.VulnClass { t.Fatal("prediction lost in JSON report") }
}
