package main

import (
	"fmt"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestGNNDiagnosticsAccountsForOpaqueAndMissingBodies(t *testing.T) {
	result := types.NewAnalysisResult("fixture")
	result.Files = map[string]*types.FileAnalysis{"A.smali": {SmaliClass: &types.SmaliClass{Name: "test.A", Methods: []types.SmaliMethod{
		{Name: "native", ReturnType: "V", Access: types.AccessNative, Body: []string{".method native native()V", "# opaque", ".end method"}},
		{Name: "empty", ReturnType: "V"},
		{Name: "visible", ReturnType: "V", Body: []string{"const/4 v0, 0", "if-eqz v0, :done", "return-void", ":done", "return-void"}},
	}}}}
	report, indices := newGNNDiagnostics(result, "__dummy__")
	if report.MethodsDiscovered != 3 || report.MethodsScheduled != 1 || report.MethodsSkipped != 2 || len(indices) != 3 || !report.Model.Dummy {
		t.Fatalf("body coverage wrong: %+v", report)
	}
	finishGNNDiagnostics(report)
	if report.MethodsNotProcessed != 1 || report.Status != "partial" {
		t.Fatalf("missing inference hidden: %+v", report)
	}
	report.MethodsInferred = 1
	report.Cancelled = true
	finishGNNDiagnostics(report)
	if report.MethodsProcessed != 3 || report.MethodsNotProcessed != 0 || report.Status != "partial" {
		t.Fatalf("cancellation or coverage lost: %+v", report)
	}
}

func TestGNNDiagnosticRecordLimitPreservesTotalCounts(t *testing.T) {
	methods := make([]types.SmaliMethod, maxGNNDiagnosticMethods+7)
	for i := range methods {
		methods[i] = types.SmaliMethod{Name: fmt.Sprint(i), ReturnType: "V", Access: types.AccessNative}
	}
	result := types.NewAnalysisResult("fixture")
	result.Files = map[string]*types.FileAnalysis{"A.smali": {SmaliClass: &types.SmaliClass{Name: "A", Methods: methods}}}
	report, _ := newGNNDiagnostics(result, "model.json")
	finishGNNDiagnostics(report)
	if report.MethodsDiscovered != len(methods) || report.MethodsSkipped != len(methods) ||
		report.DiagnosticsOmitted != 7 || len(report.Methods) != maxGNNDiagnosticMethods || report.MethodsNotProcessed != 0 {
		t.Fatalf("diagnostic cap changed coverage counts: %+v", report)
	}
}
