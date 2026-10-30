`integration-weights.json` contains fixed synthetic weights with a constant
license-bypass prediction. It tests Go → Rust model loading, graph construction,+inference and JSON report serialization. It must never be used as a production
model or as evidence of classifier accuracy or calibration.

Regenerating (36-dim v3 tensors; the test only asserts the bypass class and
the production quality gate, not an exact confidence):

1. Build the fixture corpus: 8 guard-style methods (label 2) + 8 computation
   methods (label 0) as single-method smali files, export with
   `bin/gnnprobe.exe <dir> <weights> --dataset-out <f> --label 2` and
   `--benign-confirmed` respectively, then set every record's `apk_path`
   to one group.
2. `gnn-train --dataset <dir> --confirmed-only --allow-graph-split
   --epochs 300 --seed 11 --out testdata/gnn/integration-weights.json`
3. `go test -tags omnisec_ml_gnn -run TestGNNIntegrationFixedWeights
   ./pkg/cmd/analyzer/` must pass.
