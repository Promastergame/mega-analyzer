//go:build (!omnisec_ml_gnn || !cgo) && !(js && wasm)

package main

import (
	"context"

	"mega-analyzer/pkg/internal/types"
)

// runGNNClassification is a no-op stub used when the binary is built without
// GNN support. It only runs when weights were found, so warn loudly instead
// of skipping silently.
func (a *App) runGNNClassification(ctx context.Context, result *types.AnalysisResult, modelPath string) error {
	_ = ctx
	diagnostics, _ := newGNNDiagnostics(result, modelPath)
	diagnostics.Status, diagnostics.Reason = "unavailable", "binary_without_gnn_support"
	finishGNNDiagnostics(diagnostics)
	diagnostics.Status = "unavailable"
	result.GNNDiagnostics = diagnostics
	result.GNNFindings = nil
	a.output.Warning("GNN weights found (%s), but this binary was built without GNN support.", modelPath)
	a.output.Warning("Rebuild with: go build -tags omnisec_ml_gnn (cgo required).")
	return nil
}
