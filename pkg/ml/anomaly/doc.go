// Package anomaly provides dependency-free, deterministic unsupervised
// anomaly detection and approximate similarity search over the numeric
// feature vectors produced by mega-analyzer's ML pipeline
// (see pkg/ml/featurestore).
//
// # Motivation
//
// The existing ML subsystem is strong at *supervised* scoring (logistic
// regression, gradient boosting, multiclass, conformal calibration) but it
// had no *unsupervised* layer. Two capabilities were missing entirely:
//
//  1. Anomaly detection — flagging targets/methods whose feature vectors
//     look nothing like anything seen before, without needing labels.
//  2. Similarity search / historical comparison — "what past targets are
//     most similar to this one?" for recommendation and triage.
//
// This package fills both gaps with three cooperating primitives that share
// the same [][]float64 matrix contract used by scaler.go, gbt.go and
// eval.go, so it drops straight into the existing pipeline:
//
//   - IsolationForest  — sub-linear unsupervised anomaly scoring in [0,1].
//   - Baseline         — streaming per-feature statistics (Welford) that
//     yield explainable z-score attributions.
//   - LSHIndex         — random-hyperplane SimHash index for fast
//     approximate nearest-neighbour similarity search.
//   - Detector         — a facade that fuses the three into one explainable
//     Result (anomaly score + top contributing features +
//     nearest historical neighbours).
//
// Design goals (mirroring the rest of pkg/ml):
//   - No new dependencies — standard library only in the core.
//   - Fully deterministic — every randomised step is seeded.
//   - Cheap — training and scoring are streaming / sub-linear where possible.
//   - Explainable — every score decomposes into per-feature contributions.
package anomaly
