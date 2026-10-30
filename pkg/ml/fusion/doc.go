// Package fusion is mega-analyzer's central CPU-first intelligence layer.
//
// It does NOT replace the existing supervised models (GBT, logistic,
// multiclass), the HDC engine, the ensemble, or the unsupervised anomaly
// package. Instead it sits above them and combines their weak signals into a
// single, explainable, uncertainty-aware decision — the "strong learner"
// assembled from many cheap ones.
//
// Everything here is designed for a 4-core, CUDA-free machine (e.g. an Intel
// i5-3340):
//
//   - No GPU, no Transformers, no heavy dependencies — standard library only
//     in the core, plus the sibling pkg/ml/anomaly and pkg/ml/featurestore.
//   - Deterministic: identical inputs and seeds produce identical output.
//   - Cheap: O(dims) online updates, sub-linear similarity recall, no full
//     retraining loop.
//   - Explainable: every decision decomposes into ranked, signed evidence.
//
// Components:
//
//   - FusionEngine    — weighted signal fusion with agreement/uncertainty
//     modelling and human-readable explanations (Phase 3/7).
//   - OnlineLogistic  — AdaGrad incremental classifier for the continuous
//     learning loop, no full retrain required (Phase 5).
//   - FeatureMonitor  — online feature importance, quality/uselessness,
//     drift, correlation and adaptive weighting (Phase 4).
//   - KnowledgeMemory — SimHash-LSH similarity recall + online clustering +
//     label-aggregated resemblance (Phase 6).
//   - Intelligence    — the facade that wires supervised providers, the
//     anomaly detector, the online model and the memory
//     into one Analyze/Learn API (Phase 3/9).
package fusion
