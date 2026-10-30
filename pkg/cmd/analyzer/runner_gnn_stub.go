//go:build !omnisec_ml_gnn || !cgo

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
	_ = result
	a.output.Warning("GNN weights found (%s), but this binary was built without GNN support.", modelPath)
	a.output.Warning("Rebuild with: go build -tags omnisec_ml_gnn (cgo required).")
	return nil
}
