// Package featurestore is a unified per-target feature container shared by
// the Go ML pipeline and the Rust HDC engine.
//
// Why this exists:
//
// Before this package, structural signals (ASTs, opcodes, control-flow
// patterns), behavioral signals (sandbox runs, runtime traces), and HDC
// similarities (Aetrium anchor matches) lived in three different
// representations that never met. The Go ML model never saw HDC
// similarities, and the HDC engine never benefited from the Go-side
// behavioral metrics. FeatureStore is the converging point: every signal
// becomes a named float64 stored under a stable key, plus typed metadata
// describing where it came from.
//
// The contract is intentionally minimal — just a typed map with explicit
// origin tracking — so any model in pkg/ml (LR, RF, GBT) and any HDC
// integration (rust_bridge.go) can produce or consume feature vectors
// without coupling to each other's internals.
package featurestore

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Origin describes where a feature value came from. The string is part of
// the on-disk format if a store is serialized, so values must remain stable.
type Origin string

const (
	// OriginStructural marks features derived from static structure: AST
	// shapes, IR opcode counts, control-flow graph metrics.
	OriginStructural Origin = "structural"

	// OriginBehavioral marks features observed at runtime or in sandbox
	// dynamic analysis: syscall counts, file accesses, network beacons.
	OriginBehavioral Origin = "behavioral"

	// OriginHDC marks features sourced from the Rust HDC / Aetrium engine,
	// typically Jaccard similarities to specific anchors and aggregate
	// statistics over those similarities.
	OriginHDC Origin = "hdc"

	// OriginFeedback marks features that encode prior analyst decisions
	// (e.g., "this anchor was confirmed N times on this target family").
	OriginFeedback Origin = "feedback"

	// OriginDerived marks features computed by combining other features —
	// useful for clearly separating raw inputs from engineered ones.
	OriginDerived Origin = "derived"
)

// Feature is a single named scalar with an origin tag. Vectorisation
// preserves order across runs by using FeatureStore.SortedKeys.
type Feature struct {
	Name   string
	Value  float64
	Origin Origin
}

// FeatureStore is a thread-safe per-target feature bag. Concurrent reads
// during inference are common (the runner pipelines targets), so we accept
// the small lock cost over a sync.Map to keep the iteration / Vector path
// deterministic.
type FeatureStore struct {
	mu       sync.RWMutex
	features map[string]Feature
}

// New creates an empty store.
func New() *FeatureStore {
	return &FeatureStore{features: make(map[string]Feature)}
}

// Set inserts or overwrites a feature. Names are case-sensitive and must be
// non-empty. Returns an error rather than panicking so callers in hot paths
// can decide whether the failure is fatal.
func (fs *FeatureStore) Set(name string, value float64, origin Origin) error {
	if name == "" {
		return errors.New("featurestore: empty feature name")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.features[name] = Feature{Name: name, Value: value, Origin: origin}
	return nil
}

// Get returns the feature and a found flag.
func (fs *FeatureStore) Get(name string) (Feature, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	f, ok := fs.features[name]
	return f, ok
}

// Value is a convenience that returns the value or `defaultVal` if missing.
// Useful when assembling vectors that should be tolerant to missing signals
// rather than failing the whole pipeline.
func (fs *FeatureStore) Value(name string, defaultVal float64) float64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	if f, ok := fs.features[name]; ok {
		return f.Value
	}
	return defaultVal
}

// Len returns the number of features currently stored.
func (fs *FeatureStore) Len() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.features)
}

// SortedKeys returns feature names in deterministic ascending order. This
// is the canonical ordering used to build feature vectors, so any model
// trained on one schema can score on another store as long as the schemas
// agree on names.
func (fs *FeatureStore) SortedKeys() []string {
	fs.mu.RLock()
	keys := make([]string, 0, len(fs.features))
	for k := range fs.features {
		keys = append(keys, k)
	}
	fs.mu.RUnlock()
	sort.Strings(keys)
	return keys
}

// Vector materialises the feature values in the order specified by `schema`.
// Missing features are filled with `missingFill`. Returns the names actually
// produced (in order) plus the values; the names match `schema` and exist
// even when fallbacks were applied so callers can audit which features were
// truly present at scoring time.
func (fs *FeatureStore) Vector(schema []string, missingFill float64) ([]string, []float64) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := make([]float64, len(schema))
	for i, name := range schema {
		if f, ok := fs.features[name]; ok {
			out[i] = f.Value
		} else {
			out[i] = missingFill
		}
	}
	// Return a copy of schema so callers can safely retain the slice.
	names := append([]string(nil), schema...)
	return names, out
}

// AutoVector materialises every feature in the store using SortedKeys. It is
// the right choice when training a model on the first batch of data and
// the schema is whatever happens to be present.
func (fs *FeatureStore) AutoVector() ([]string, []float64) {
	keys := fs.SortedKeys()
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	values := make([]float64, len(keys))
	for i, k := range keys {
		values[i] = fs.features[k].Value
	}
	return keys, values
}

// FilterByOrigin returns the names (sorted) of features whose origin matches.
// Useful for diagnostics ("how many HDC features did we get this run?")
// and for ablation experiments ("score with structural-only").
func (fs *FeatureStore) FilterByOrigin(origin Origin) []string {
	fs.mu.RLock()
	out := []string{}
	for k, f := range fs.features {
		if f.Origin == origin {
			out = append(out, k)
		}
	}
	fs.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Merge folds another store into this one. Conflicts use `overwrite` to
// decide; useful when an enrichment step (HDC) augments an existing
// feature set.
func (fs *FeatureStore) Merge(other *FeatureStore, overwrite bool) error {
	if other == nil {
		return nil
	}
	other.mu.RLock()
	defer other.mu.RUnlock()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for k, v := range other.features {
		if _, exists := fs.features[k]; exists && !overwrite {
			continue
		}
		fs.features[k] = v
	}
	return nil
}

// Clone returns a deep copy. Use when shipping a snapshot to a goroutine
// that may mutate concurrently.
func (fs *FeatureStore) Clone() *FeatureStore {
	out := New()
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	for k, v := range fs.features {
		out.features[k] = v
	}
	return out
}

// Snapshot returns a stable copy of all features, useful for logging.
func (fs *FeatureStore) Snapshot() []Feature {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := make([]Feature, 0, len(fs.features))
	for _, v := range fs.features {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// String returns a compact, deterministic textual rendering for debugging.
func (fs *FeatureStore) String() string {
	snap := fs.Snapshot()
	if len(snap) == 0 {
		return "FeatureStore{}"
	}
	out := "FeatureStore{"
	for i, f := range snap {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s(%s)=%g", f.Name, f.Origin, f.Value)
	}
	out += "}"
	return out
}
