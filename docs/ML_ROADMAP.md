# ML Roadmap: machine-learning strategy in Mega-Analyzer

[Русский](ML_ROADMAP.ru.md)

The guiding philosophy for ML in Mega-Analyzer: **"accumulate experience — make the models smarter with every run."** The platform targets fully local, private and fast inference with no external cloud dependencies.

---

## Current state (what already works)

Several layers of classification and intelligent analysis are integrated today:

| Model / method | Use | Technology / language | Notes |
| :--- | :--- | :--- | :--- |
| **HDC auto-naming** | AI auto-naming of functions and variables | Rust (`omnisec-hdc`) + Zig SIMD | 2048-bit hypervectors, offline, <10 MB RAM, Jaccard parity. |
| **Random Forest** | Vulnerability scoring in code | Go (own implementation) | Trains on local features, weighted fit, stable trees. |
| **GBT (gradient-boosted trees)** | Anomaly and malware detection | Go (own implementation) | Log-loss objective, early stopping. |
| **GNN (graph neural network)** | CFG/PDG control-flow analysis | Rust (`omnisec-ml-gnn`) | Spectral graph classification across 8 vulnerability classes. |
| **Platt calibration** | Probability calibration | Go | Turns raw classifier outputs into honest confidence. |
| **Explainable AI** | Explaining findings | Go / HTML | SHAP-inspired local feature-importance breakdown. |

---

## In development (current work)

1. **Training pipeline from `history.json`**
   * Automatic feature extraction and labelling driven by the user feedback log (`~/.analyzer/history.json`).
   * Multi-tier training: hard labels from the user ➔ soft labels ➔ heuristic pseudo-labels.
2. **Keyword relevance scorer**
   * Logistic regression with L2 regularization for dynamic false-positive filtering based on contextual tokens.
3. **Drift monitor**
   * Tracks PSI (population stability index) and Kullback–Leibler divergence to detect drift between the training set and the code being scanned.
   * Automatically alerts the user when a model needs retraining (`-ml-stats`).

---

## Future (roadmap)

### Stage 1: conformal prediction
* Guaranteed uncertainty-interval estimates. The model should say when it is "not sure" instead of emitting a falsely high probability.

### Stage 2: local incremental learning
* Partial on-the-fly retraining (`PartialFit`) directly while marking false positives in the TUI or the HTML report.

### Stage 3: community signatures
* Safe export of local model weights to share anonymized experience with other developers — without exporting the analyzed source code.
