# anomaly — unsupervised detection & similarity search

`pkg/ml/anomaly` adds the unsupervised layer that the mega-analyzer ML
subsystem was missing. It is **standard-library only** in its core, fully
**deterministic** (every random step is seeded), and integrates with the
existing `pkg/ml/featurestore` convergence layer without touching any existing
file — so it cannot break the current build.

## Why it exists

The subsystem already had strong *supervised* models (logistic regression,
gradient boosting, multiclass, conformal calibration, drift monitoring). It had
no way to answer two questions that matter for a serious analysis platform:

1. **"Is this target unlike anything we've seen?"** → anomaly detection.
2. **"What past targets look most like this one?"** → similarity search /
   historical comparison / recommendation.

## Components

| Type | Role | Algorithm |
|------|------|-----------|
| `IsolationForest` | Unsupervised anomaly score in `[0,1]` | Isolation Forest (Liu et al.) |
| `Baseline` / `Welford` | Streaming per-feature stats + explainable z-scores | Welford online variance |
| `LSHIndex` | Approximate nearest-neighbour similarity search | Random-hyperplane SimHash + cosine refine |
| `Detector` | Fused, explainable facade | combines the three |

## Quick start

```go
import (
    "mega-analyzer/pkg/ml/anomaly"
    "mega-analyzer/pkg/ml/featurestore"
)

// stores: []*featurestore.FeatureStore built by the pipeline.
det, err := anomaly.NewDetectorFromStores(stores, ids, anomaly.DefaultConfig())
if err != nil { /* handle */ }

res, _ := det.AnalyzeStore(current)
if res.IsAnomaly {
    // res.Score        -> isolation-forest anomaly score
    // res.TopContributors -> which features drove the verdict (z-scores)
    // res.Neighbors    -> most similar historical targets
}
```

## Design guarantees

- **No new dependencies.** Core uses only `math`, `math/rand`, `math/bits`,
  `sort`, `errors`. The single adapter file imports `featurestore` (stdlib-only,
  no import cycle).
- **Deterministic.** Same seed + same data ⇒ identical scores and rankings.
- **Explainable.** Every verdict decomposes into ranked per-feature
  contributions with mean/σ context.
- **Cheap.** Scoring is O(trees · depth); baseline updates are O(1) memory.

## Tests & benchmarks

```bash
go test ./pkg/ml/anomaly/...
go test -bench=. ./pkg/ml/anomaly/...
```

Covers Welford correctness vs. the closed-form variance, isolation-forest
anomaly ordering and determinism, LSH nearest-neighbour retrieval, the fused
detector end-to-end, and edge cases (empty/ragged input, zero-variance
features, untrained guards).
