package anomaly

import (
	"sort"

	fs "mega-analyzer/pkg/ml/featurestore"
)

// This adapter is the only file that couples the anomaly package to the rest
// of pkg/ml. It imports featurestore (stdlib-only, no cycle) so callers can
// go straight from the pipeline's feature bags to a trained Detector.

// UnionSchema returns the sorted union of feature names across every store.
// Use it to build a stable schema before vectorising a heterogeneous corpus.
func UnionSchema(stores []*fs.FeatureStore) []string {
	set := make(map[string]struct{})
	for _, s := range stores {
		if s == nil {
			continue
		}
		for _, k := range s.SortedKeys() {
			set[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BuildMatrix materialises a fixed-schema matrix from many feature stores.
// Missing features are filled with missingFill so a ragged corpus still
// yields a dense, model-ready matrix. Nil stores are skipped.
func BuildMatrix(stores []*fs.FeatureStore, schema []string, missingFill float64) [][]float64 {
	out := make([][]float64, 0, len(stores))
	for _, s := range stores {
		if s == nil {
			continue
		}
		_, vec := s.Vector(schema, missingFill)
		out = append(out, vec)
	}
	return out
}

// NewDetectorFromStores is the one-call path from the feature store to a
// trained, explainable Detector. It derives a stable union schema, builds the
// matrix, and fits the detector. ids (optional) label rows for similarity
// search; pass nil to auto-generate them.
func NewDetectorFromStores(stores []*fs.FeatureStore, ids []string, cfg Config) (*Detector, error) {
	schema := UnionSchema(stores)
	matrix := BuildMatrix(stores, schema, 0)
	d := NewDetector(schema, cfg)
	if err := d.Fit(matrix, ids); err != nil {
		return nil, err
	}
	return d, nil
}

// AnalyzeStore vectorises a single store against the detector's schema and
// analyses it. This keeps the schema alignment concern inside the package so
// callers never have to hand-align columns.
func (d *Detector) AnalyzeStore(store *fs.FeatureStore) (Result, error) {
	_, vec := store.Vector(d.schema, 0)
	return d.Analyze(vec)
}
