package main

import (
	"math"

	"mega-analyzer/pkg/ml/gnn"
	"mega-analyzer/pkg/ml/gnncache"
)

// GNN quality-gate floors. They live here (untagged) rather than in
// runner_gnn.go (cgo-tagged) so tests and stub builds share them.
const (
	gnnMinConfidence = float32(0.55)
	gnnMinMargin     = float32(0.10)
)

// gnnPredictionMargin validates a cached or freshly inferred distribution and
// returns the gap between the top two classes. Confidence alone is unreliable
// for an eight-way classifier: a near-tie should not become a security finding.
func gnnPredictionMargin(pred *gnncache.Prediction) (float32, bool) {
	if pred == nil || pred.PredictedClass < 0 || pred.PredictedClass >= len(pred.ClassProbs) ||
		len(pred.ClassProbs) != gnn.NumVulnClasses || !isFiniteProbability(pred.Confidence) {
		return 0, false
	}
	bestIndex := -1
	best, second := float32(-1), float32(-1)
	var sum float64
	for i, probability := range pred.ClassProbs {
		if !isFiniteProbability(probability) {
			return 0, false
		}
		sum += float64(probability)
		if probability > best {
			second = best
			best = probability
			bestIndex = i
		} else if probability > second {
			second = probability
		}
	}
	if math.Abs(sum-1) > 1e-3 || bestIndex != pred.PredictedClass ||
		math.Abs(float64(best-pred.Confidence)) > 1e-5 {
		return 0, false
	}
	return best - second, true
}

// gnnMinConfidenceForClass returns the minimum accepted confidence for a
// vulnerability class. Calibrated on the golden set (clean Mindustry/FNAF as
// negatives; modmenu/PairIP/Morphe methods as positives — see train logs):
//
//   - license-check 0.80: billing-library code (Play Billing, billingclient,
//     engine IAB managers) genuinely looks like license verification, so the
//     global 0.55 admits hundreds of findings per clean game. 0.80 keeps the
//     substantive TP (connectToLicensingService, ResponseValidator at
//     0.82-0.93) while dropping one-liner lambdas that are structurally
//     indistinguishable from benign.
//   - repack-marker 0.60: 108/445 TP at 25 FP on the calibration pool;
//     0.65 already halves recall (95) for little FP gain.
//   - signature-spoof 0.60: FP vanish above 0.60 (5 at 0.60, 0 at 0.80);
//     recall is a model problem (see below), not a threshold one.
//   - dynamic-load 0.65: classloader TP hold 0.9+, FP tail cut.
//   - default 0.55: license-bypass never fires on clean data, and
//     integrity-tamper/native-bridge are silent under v10 weights — no
//     evidence for raising them yet. Revisit when the model changes.
func gnnMinConfidenceForClass(vulnName string) float32 {
	switch vulnName {
	case "license-check":
		return 0.80
	case "repack-marker":
		return 0.60
	case "signature-spoof":
		return 0.60
	case "dynamic-load":
		return 0.65
	default:
		return gnnMinConfidence
	}
}

// gnnLicenseLibraryPrefixes are known billing-library packages whose methods
// structurally ARE license verification (Play Billing internals) but are
// never actionable findings: every clean game with in-app purchases lights
// them up (~420 FP per two calibration games at 0.80). Real findings point
// at app/engine code that CALLS billing (IABillingManager, LicenseClient),
// which is unaffected. Mirrors the pipeline's stock-FP allowlisting.
var gnnLicenseLibraryPrefixes = []string{
	"com.google.android.gms.internal.play_billing.",
	"com.android.billingclient.api.",
}

// gnnLibrarySuppressed reports whether a finding should be dropped as
// library noise. Currently only license-check inside billing libraries:
// other classes show no comparable library-shaped FP cluster.
func gnnLibrarySuppressed(method, vulnName string) bool {
	if vulnName != "license-check" {
		return false
	}
	for _, prefix := range gnnLicenseLibraryPrefixes {
		if len(method) >= len(prefix) && method[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// gnnMaxNormalizedEntropy is the third leg of the quality gate. Confidence
// checks the argmax and margin checks the top-two gap, but neither looks at
// the tail: a prediction like [0.56, 0.11, 0.055 x 6] clears both thresholds
// while the model is effectively unsure among many alternatives. Normalized
// entropy measures the whole distribution; values above this threshold are
// treated as uncertain. (With confidence >= 0.55 the maximum achievable
// normalized entropy is ~0.75, so 0.70 only rejects genuinely flat tails.)
const gnnMaxNormalizedEntropy = float32(0.70)

// gnnNormalizedEntropy returns the Shannon entropy of the distribution
// normalized to [0, 1] by log2(len(probs)): 0 = one-hot certainty,
// 1 = uniform. Callers must validate the distribution first (see
// gnnPredictionMargin); non-positive entries contribute zero, matching the
// p*log(p) -> 0 limit.
func gnnNormalizedEntropy(probs []float32) float32 {
	if len(probs) < 2 {
		return 0
	}
	var entropy float64
	for _, probability := range probs {
		if probability > 0 {
			entropy -= float64(probability) * math.Log2(float64(probability))
		}
	}
	normalized := entropy / math.Log2(float64(len(probs)))
	switch {
	case normalized < 0 || math.IsNaN(normalized):
		return 0
	case normalized > 1:
		return 1
	default:
		return float32(normalized)
	}
}

func isFiniteProbability(value float32) bool {
	return value >= 0 && value <= 1 && !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
}
