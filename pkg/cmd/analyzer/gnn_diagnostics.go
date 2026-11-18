package main

import (
	"sort"
	"strconv"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/gnn"
	"mega-analyzer/pkg/ml/gnncache"
)

const maxGNNDiagnosticMethods = 4096

func newGNNDiagnostics(result *types.AnalysisResult, modelPath string) (*types.GNNDiagnostics, map[string]int) {
	report := &types.GNNDiagnostics{SchemaVersion: 1, Status: "complete", StaticOnly: true,
		Scope:              "retained_method_graphs; licensing_and_protection_taxonomy",
		PredictionsByClass: map[string]int{}, Methods: []types.GNNMethodDiagnostic{},
		Model: types.GNNModelInfo{Path: modelPath, Format: "json", FeatureDim: gnn.ExpectedFeatureDim, Dummy: modelPath == gnncache.DummyModelPath},
	}
	for i := 0; i < gnn.NumVulnClasses; i++ {
		report.Model.Taxonomy = append(report.Model.Taxonomy, gnn.VulnClassName(gnn.VulnClass(i)))
	}
	if report.Model.Dummy {
		report.Model.Format = "random_dummy"
	}
	indices := map[string]int{}
	paths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file := result.Files[path]
		if file == nil || file.SmaliClass == nil {
			continue
		}
		for i := range file.SmaliClass.Methods {
			method := &file.SmaliClass.Methods[i]
			report.MethodsDiscovered++
			record := types.GNNMethodDiagnostic{File: path, Method: method.FullSignature(file.SmaliClass.Name),
				Status: "not_processed", Reason: "stage_not_completed"}
			switch {
			case method.Access.IsNative() || method.Access.IsAbstract():
				record.Status, record.Reason = "skipped", "native_or_abstract_body"
			case len(method.Body) < 3:
				record.Status, record.Reason = "skipped", "insufficient_method_body"
			default:
				report.MethodsScheduled++
			}
			if record.Status == "skipped" {
				report.MethodsSkipped++
			}
			if len(report.Methods) < maxGNNDiagnosticMethods {
				indices[gnnDiagnosticKey(path, i)] = len(report.Methods)
				report.Methods = append(report.Methods, record)
			} else {
				report.DiagnosticsOmitted++
			}
		}
	}
	return report, indices
}

func gnnDiagnosticKey(path string, index int) string { return path + "\x00" + strconv.Itoa(index) }

func finishGNNDiagnostics(report *types.GNNDiagnostics) {
	report.MethodsProcessed = report.MethodsInferred + report.MethodsSkipped + report.MethodsFailed
	report.MethodsNotProcessed = report.MethodsDiscovered - report.MethodsProcessed
	if report.MethodsNotProcessed < 0 {
		report.MethodsNotProcessed = 0
	}
	if report.Error != "" {
		report.Status = "partial"
		if report.MethodsInferred == 0 {
			report.Status = "unavailable"
		}
	} else if report.Cancelled || report.MethodsNotProcessed > 0 {
		report.Status = "partial"
	}
}
