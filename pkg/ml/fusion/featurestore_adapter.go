package fusion

import (
	fs "mega-analyzer/pkg/ml/featurestore"
)

// This file is the only coupling between fusion and the pipeline's feature
// store. featurestore is stdlib-only, so importing it here creates no cycle.

// AnalyzeStore vectorises a feature store against the engine schema and runs
// a full analysis, keeping schema alignment inside the package so callers in
// cfg / deobfuscation / scanners never hand-align columns.
func (in *Intelligence) AnalyzeStore(id string, store *fs.FeatureStore, extra []Evidence) (Report, error) {
	_, vec := store.Vector(in.cfg.Schema, 0)
	return in.Analyze(Sample{ID: id, Features: vec, Extra: extra})
}

// LearnStore folds a labelled feature store into the continuous-learning loop.
func (in *Intelligence) LearnStore(id string, store *fs.FeatureStore, label int, memoryLabel string) error {
	_, vec := store.Vector(in.cfg.Schema, 0)
	return in.Learn(Sample{ID: id, Features: vec}, label, memoryLabel)
}

// VectorFromStore is a small helper exposing schema-aligned vectorisation.
func (in *Intelligence) VectorFromStore(store *fs.FeatureStore) []float64 {
	_, vec := store.Vector(in.cfg.Schema, 0)
	return vec
}
