# fusion — central CPU-first intelligence layer

`pkg/ml/fusion` turns mega-analyzer's many weak ML signals into one strong,
explainable, uncertainty-aware decision. It is **additive** (no existing file
is modified), **standard-library only** in its core (plus the sibling
`pkg/ml/anomaly` and `pkg/ml/featurestore`), fully **deterministic**, and
designed to run comfortably on a 4-core, CUDA-free machine such as an
**Intel i5-3340**. No GPU, no Transformers, no heavy dependencies.

## Why this design (i5-3340 constraints)

Detection quality on this hardware comes from *combining many cheap signals*,
not from one huge model. Every component here is O(dims) per update or
sub-linear per query, so the whole engine stays interactive on large projects.

| Phase | Component | Algorithm | Cost |
|-------|-----------|-----------|------|
| 3, 7 | `FusionEngine` | weighted signal fusion + agreement/uncertainty + evidence | O(signals) |
| 5 | `OnlineLogistic` | AdaGrad incremental logistic regression | O(dims)/update |
| 4 | `FeatureMonitor` | Welford stats, Pearson label-corr, Page-Hinkley drift, adaptive weights | O(dims)/update |
| 6 | `KnowledgeMemory` | SimHash-LSH recall + online leader clustering + label aggregation | sub-linear recall |
| 3, 9 | `Intelligence` | facade fusing providers + anomaly + online + memory | — |

## The decision, explained

`Intelligence.Analyze` returns a `Report` whose `Decision.Explanation` reads:

```
Threat probability: 94%
Main factors:
1. anomaly +31%
2. gbm +27%
3. similarity +18%
4. online +18%
Confidence: High
Reason: 4 independent systems agree (agreement 92%).
```

When models disagree, the weighted dispersion lowers `Confidence`, sets
`Disagreement=true`, and switches `Recommendation` to `deep_analysis` with an
explanation of the conflict — the engine *understands uncertainty*.

## Wiring existing models in

Supervised models (GBT, logistic, multiclass, HDC) join via a tiny adapter
satisfying `ScoreProvider` — no import of the heavy `pkg/ml` root, so there is
no import cycle:

```go
type gbmProvider struct{ m *ml.GradientBoostingClassifier }
func (p gbmProvider) Name() string          { return "gbm" }
func (p gbmProvider) Weight() float64        { return 1.2 }
func (p gbmProvider) Score(x []float64) float64 { pr, _ := p.m.PredictProbability(x); return pr }
```

## Usage

```go
cfg := fusion.IntelligenceConfig{Schema: schema, Fusion: fusion.DefaultFusionConfig()}
eng := fusion.NewIntelligence(cfg, gbmProvider{gbm}, hdcProvider{hdc})
_ = eng.FitDetector(backgroundCorpus, ids) // optional unsupervised layer

rep, _ := eng.AnalyzeStore("sample-42", store, []fusion.Evidence{
    {Factor: "CFG flattening detected", Contribution: 0},
})
fmt.Println(rep.Decision.Explanation)
for _, r := range rep.Resembles { /* "family A: 87%" */ }

// Continuous learning — no full retrain:
_ = eng.LearnStore("sample-42", store, 1, "MalwareFamilyA")
```

## Feature intelligence (Phase 4)

```go
for _, f := range eng.FeatureReport() {
    // f.Importance, f.Useless, f.Drifted, f.Correlation
}
weights := eng.AdaptiveWeights()               // learned per-feature weights
pairs := monitor.DetectCorrelated(0.95)         // redundant feature pairs
```

## Tests & benchmarks

```bash
go test ./pkg/ml/fusion/...
go test -bench=. ./pkg/ml/fusion/...
```

Covers fusion consensus vs. conflict, online-learning convergence on separable
data, feature importance / uselessness / drift, similarity resemblance and
clustering, the end-to-end intelligence loop, and benchmarks for the hot paths.
