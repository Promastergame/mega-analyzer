package deobfuscation

// ═══════════════════════════════════════════════════════════════════════════════
// FUSION INTELLIGENCE INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// This file wires the pkg/ml/fusion Intelligence engine into the deobfuscation
// pipeline. After every Analyze pass has run (CFF, opaque predicates, dead
// code, string decryption), the results are projected onto a fixed-width
// feature vector and fed to an Intelligence engine that fuses them into a
// single, explainable FusionReport attached to DeobfuscationResult.
//
// Feature schema (14 dimensions — see fusionSchema below):
//
//	[0]  cff_detected          — 1.0 if CFF dispatcher found, else 0
//	[1]  cff_confidence        — CFF confidence [0,1]
//	[2]  opaque_count_norm     — opaque predicate count / 10, clamped to 1
//	[3]  dead_branches_norm    — dead branches eliminated / 10, clamped to 1
//	[4]  dead_nodes_norm       — dead nodes / 10, clamped to 1
//	[5]  recovered_strings_norm— recovered strings / 10, clamped to 1
//	[6]  reduction_percent     — CFG complexity reduction [0,1]
//	[7]  original_complexity   — cyclomatic complexity / 50, clamped to 1
//	[8]  high_entropy_strings  — fraction of recovered strings with entropy>6.5
//	[9]  base64_ratio          — fraction of recovered strings classified base64
//	[10] hex_ratio             — fraction of recovered strings classified hex
//	[11] composite_confidence  — scoreConfidence output [0,1]
//	[12] string_coverage       — recovered strings / (original_complexity+1)
//	[13] has_any_signal        — 1.0 if ANY deobfuscation signal was present

import (
	"fmt"
	"math"
	"sync"

	"mega-analyzer/pkg/ml/fusion"
)

// FusionReport wraps the intelligence decision and its feature projection so
// downstream consumers (CLI, server, NCER) can access both the explainable
// verdict and the raw feature vector.
type FusionReport struct {
	Decision     fusion.Decision `json:"decision"`
	Features     []float64       `json:"features"`
	FeatureNames []string        `json:"feature_names"`
}

// fusionSchema is the fixed ordered list of feature names fed to Intelligence.
var fusionSchema = []string{
	"cff_detected",
	"cff_confidence",
	"opaque_count_norm",
	"dead_branches_norm",
	"dead_nodes_norm",
	"recovered_strings_norm",
	"reduction_percent",
	"original_complexity",
	"high_entropy_strings",
	"base64_ratio",
	"hex_ratio",
	"composite_confidence",
	"string_coverage",
	"has_any_signal",
}

// defaultFusionConfig builds an IntelligenceConfig tuned for the deobfuscation
// domain: feature dimensions match fusionSchema, the fusion threshold is
// lowered to 0.45 (obfuscation evidence tends to be weaker than malware
// imports), and MinSignals is set to 2 because we only have one ScoreProvider
// plus the online model.
func defaultFusionConfig() fusion.IntelligenceConfig {
	return fusion.IntelligenceConfig{
		Schema: fusionSchema,
		Fusion: fusion.FusionConfig{
			DisagreementStd: 0.20,
			Threshold:       0.45,
			MinSignals:      2,
		},
		AnomalyWeight:    0.8,
		SimilarityWeight: 0.7,
		OnlineWeight:     1.0,
		OnlineLR:         0.1,
		OnlineL2:         1e-5,
	}
}

// sharedIntelligence is the package-level Intelligence instance that persists
// across Analyze calls so the online model accumulates knowledge incrementally.
// It is initialised once via sync.Once in getIntelligence().
var (
	sharedIntel *fusion.Intelligence
	intelOnce   sync.Once
	// fusion.Intelligence mutates its online model, feature monitor and
	// similarity memory on every Analyze, and none of that is internally
	// synchronised. AnalyzeAll runs Analyze across GOMAXPROCS goroutines, so
	// the singleton needs a lock of its own — the doc comment claimed a
	// sync.Once that was never there, and the map writes inside were a live
	// `concurrent map writes` crash.
	intelMu sync.Mutex
)

// getIntelligence returns the package-level Intelligence singleton, creating
// it on first call. The built-in CompositeConfidenceProvider is registered as
// the sole ScoreProvider.
func getIntelligence() *fusion.Intelligence {
	intelOnce.Do(func() {
		sharedIntel = fusion.NewIntelligence(
			defaultFusionConfig(),
			compositeConfidenceProvider{},
		)
	})
	return sharedIntel
}

// resetIntelligence drops the singleton so the next getIntelligence rebuilds
// it. Tests use this to start from a clean model; clearing sharedIntel alone
// no longer works now that construction is guarded by a sync.Once.
func resetIntelligence() {
	intelMu.Lock()
	defer intelMu.Unlock()
	sharedIntel = nil
	intelOnce = sync.Once{}
}

// compositeConfidenceProvider adapts the scoreConfidence scalar (already
// computed by the engine) into a fusion.ScoreProvider so it participates in
// the weighted fusion alongside the online-learned and similarity signals.
type compositeConfidenceProvider struct{}

func (compositeConfidenceProvider) Name() string    { return "composite_confidence" }
func (compositeConfidenceProvider) Weight() float64 { return 1.2 }

// Score extracts the composite_confidence feature (index 11) directly from
// the feature vector, avoiding a redundant computation.
func (compositeConfidenceProvider) Score(x []float64) float64 {
	if len(x) > 11 {
		return x[11]
	}
	return 0
}

// projectFeatures converts a DeobfuscationResult into the 14-dimensional
// feature vector consumed by the Intelligence engine.
func projectFeatures(r *DeobfuscationResult) []float64 {
	x := make([]float64, len(fusionSchema))

	// [0] cff_detected
	if r.CFFFDetected {
		x[0] = 1.0
	}
	// [1] cff_confidence
	x[1] = clamp01(r.CFFConfidence)

	// [2] opaque_count_norm
	x[2] = clamp01(float64(r.OpaquePredicatesFound) / 10.0)

	// [3] dead_branches_norm
	x[3] = clamp01(float64(r.DeadBranchesEliminated) / 10.0)

	// [4] dead_nodes_norm
	x[4] = clamp01(float64(r.DeadNodesFound) / 10.0)

	// [5] recovered_strings_norm
	x[5] = clamp01(float64(len(r.RecoveredStrings)) / 10.0)

	// [6] projected_reduction_percent
	x[6] = clamp01(r.ProjectedReductionPercent / 100.0)

	// [7] original_complexity (normalised over 50)
	x[7] = clamp01(float64(r.OriginalComplexity) / 50.0)

	// [8–10] per-encoding ratios over recovered strings
	if n := len(r.RecoveredStrings); n > 0 {
		var highEnt, b64, hex float64
		for _, rs := range r.RecoveredStrings {
			switch rs.Encoding {
			case EncodingHighEntropy.String():
				highEnt++
			case EncodingBase64.String():
				b64++
			case EncodingHex.String():
				hex++
			}
			// also count by raw entropy value if Encoding not set
			if rs.Encoding == "" && rs.Entropy > 6.5 {
				highEnt++
			}
		}
		nf := float64(n)
		x[8] = highEnt / nf
		x[9] = b64 / nf
		x[10] = hex / nf
	}

	// [11] composite_confidence — the heuristic scorer output
	x[11] = clamp01(r.Confidence)

	// [12] string_coverage: recovered strings per unit of complexity
	denom := float64(r.OriginalComplexity + 1)
	x[12] = clamp01(float64(len(r.RecoveredStrings)) / denom)

	// [13] has_any_signal
	if r.IsObfuscated() {
		x[13] = 1.0
	}

	return x
}

// buildSampleID constructs a deterministic sample identifier for a result.
func buildSampleID(r *DeobfuscationResult) string {
	if r.MethodName == "" {
		return "unknown"
	}
	if r.ClassName != "" {
		return fmt.Sprintf("%s.%s", r.ClassName, r.MethodName)
	}
	return r.MethodName
}

// buildExtraEvidence converts discrete deobfuscation signals into
// fusion.Evidence entries so they appear in the decision's evidence list.
func buildExtraEvidence(r *DeobfuscationResult) []fusion.Evidence {
	var ev []fusion.Evidence

	if r.CFFFDetected {
		ev = append(ev, fusion.Evidence{
			Factor:       "cff_detected",
			Contribution: math.Min(r.CFFConfidence*0.5, 0.5),
			Detail:       fmt.Sprintf("CFF dispatcher at node %d (confidence %.0f%%)", r.CFFDispatcherNode, r.CFFConfidence*100),
		})
	}
	if r.OpaquePredicatesFound > 0 {
		ev = append(ev, fusion.Evidence{
			Factor:       "opaque_predicates",
			Contribution: clamp01(float64(r.OpaquePredicatesFound) * 0.05),
			Detail:       fmt.Sprintf("%d opaque predicate(s) resolved", r.OpaquePredicatesFound),
		})
	}
	if r.DeadNodesFound > 0 {
		ev = append(ev, fusion.Evidence{
			Factor:       "dead_code",
			Contribution: clamp01(float64(r.DeadNodesFound) * 0.03),
			Detail:       fmt.Sprintf("%d dead node(s) eliminated", r.DeadNodesFound),
		})
	}
	if len(r.RecoveredStrings) > 0 {
		ev = append(ev, fusion.Evidence{
			Factor:       "encrypted_strings",
			Contribution: clamp01(float64(len(r.RecoveredStrings)) * 0.05),
			Detail:       fmt.Sprintf("%d encrypted string(s) recovered", len(r.RecoveredStrings)),
		})
	}
	return ev
}

// runFusionIntelligence is the final pass called by Engine.Analyze after all
// structural passes have completed. It projects r onto the feature vector,
// queries the package-level Intelligence engine, and attaches a FusionReport
// to r.
//
// No online update happens here. The only label available at this point is
// IsObfuscated(), which is computed from the very features being fed in, so
// training on it taught the model nothing it did not already encode and let
// state from one APK drift into the scoring of the next. Wire Learn to
// confirmed analyst feedback if online adaptation is wanted.
func runFusionIntelligence(r *DeobfuscationResult) *FusionReport {
	intel := getIntelligence()

	features := projectFeatures(r)
	extra := buildExtraEvidence(r)

	sample := fusion.Sample{
		ID:       buildSampleID(r),
		Features: features,
		Extra:    extra,
	}

	intelMu.Lock()
	rep, err := intel.Analyze(sample)
	intelMu.Unlock()
	if err != nil {
		// Should never happen with a well-formed feature vector; return a
		// low-confidence stub so callers are never blocked.
		return &FusionReport{
			Decision:     fusion.Decision{Explanation: "fusion analysis unavailable: " + err.Error()},
			Features:     features,
			FeatureNames: fusionSchema,
		}
	}

	return &FusionReport{
		Decision:     rep.Decision,
		Features:     features,
		FeatureNames: fusionSchema,
	}
}
