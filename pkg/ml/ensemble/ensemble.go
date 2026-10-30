// Package ensemble provides an additive, dependency-light scoring layer
// that augments Mega Analyzer's existing ML patch predictor.
//
// The ensemble does not replace the legacy scorer — it consumes the same
// MethodInfo structures, computes a richer feature set, and returns a
// blended, calibrated score per method. The fused score is exposed via
// the Boost helper so callers can re-rank ScoredMethod / PatchPoint
// slices without rewriting the existing pipeline.
//
// Design goals:
//   - No new heavy deps — we only use ml.MethodInfo (read-only).
//   - Fully deterministic — same input, same output.
//   - Cheap — sub-millisecond per method on typical smali bodies.
//   - Explainable — every signal exposes its contribution.
package ensemble

import (
	"math"
	"sort"
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD VIEW
// ═══════════════════════════════════════════════════════════════════════════════

// MethodView is the subset of MethodInfo the ensemble actually needs. We keep
// it as a small interface so callers can adapt their own structs without
// importing pkg/ml (which would create a cycle).
type MethodView interface {
	GetName() string
	GetFullSignature() string
	GetReturnType() string
	GetInstructionCount() int
	GetRegisterCount() int
	GetIfCheckCount() int
	GetReturnCount() int
	GetCalls() []string
	GetStringConsts() []string
	GetRawBody() []string
	GetIsAppCode() bool
	GetIsLibrary() bool
	GetIsCallback() bool
	GetIsConstructor() bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURES
// ═══════════════════════════════════════════════════════════════════════════════

// Features is a fully-realised feature vector for one method.
//
// Every field is bounded into a sensible range so downstream linear models
// stay numerically stable.
type Features struct {
	// Structural
	Cyclomatic    float64 // 1..50, log-bounded
	NestingDepth  float64 // 0..16
	BranchDensity float64 // branches / instructions
	ReturnDensity float64 // returns / instructions
	BodyLength    int     // raw line count
	UniqueOpcodes int     // distinct opcode tokens

	// Information theoretic
	StringEntropy float64 // [0..8] Shannon
	BodyEntropy   float64 // [0..8] body-text Shannon
	BigramEntropy float64 // [0..16] body-text bigram Shannon

	// Semantic
	SecurityCallRatio float64 // security calls / total calls
	NetworkCallRatio  float64
	CryptoCallRatio   float64
	DynamicCallRatio  float64 // reflection, classloader, dex
	ObfuscationScore  float64 // 0..1 — short identifiers, binary strings
	NameQualityScore  float64 // 0..1 — descriptive names = high
	TaintFlowScore    float64 // 0..1 — source→sink confidence

	// Context
	IsAppCode     bool
	IsLibrary     bool
	IsCallback    bool
	IsConstructor bool
}

// FeatureNames is the fixed, ordered feature list shared by the explain pass
// and the ensemble trainer/scorer. Never reorder existing entries, append only.
var FeatureNames = []string{
	"cyclomatic",
	"nesting_depth",
	"branch_density",
	"return_density",
	"body_length",
	"unique_opcodes",
	"string_entropy",
	"body_entropy",
	"bigram_entropy",
	"security_call_ratio",
	"network_call_ratio",
	"crypto_call_ratio",
	"dynamic_call_ratio",
	"obfuscation_score",
	"name_quality_score",
	"taint_flow_score",
	"is_app_code",
	"is_library",
	"is_callback",
	"is_constructor",
}

// Flatten converts the Features struct into a FeatureNames-ordered slice of floats.
func (f Features) Flatten() []float64 {
	boolToFloat := func(b bool) float64 {
		if b {
			return 1.0
		}
		return 0.0
	}
	return []float64{
		f.Cyclomatic,
		f.NestingDepth,
		f.BranchDensity,
		f.ReturnDensity,
		float64(f.BodyLength),
		float64(f.UniqueOpcodes),
		f.StringEntropy,
		f.BodyEntropy,
		f.BigramEntropy,
		f.SecurityCallRatio,
		f.NetworkCallRatio,
		f.CryptoCallRatio,
		f.DynamicCallRatio,
		f.ObfuscationScore,
		f.NameQualityScore,
		f.TaintFlowScore,
		boolToFloat(f.IsAppCode),
		boolToFloat(f.IsLibrary),
		boolToFloat(f.IsCallback),
		boolToFloat(f.IsConstructor),
	}
}

// Score is the blended ensemble result.
type Score struct {
	// Final risk score in [0..100], calibrated to be comparable to the
	// legacy patch_scorer.
	Final float64 `json:"final"`

	// Confidence in [0..1] — high when multiple signals agree.
	Confidence float64 `json:"confidence"`

	// Contributions explains how the score was assembled. Sums to Final.
	Contributions []Contribution `json:"contributions"`

	// Features is the underlying feature vector (debugging / drift tracking).
	Features Features `json:"features"`
}

// Contribution describes a single signal's influence on the final score.
type Contribution struct {
	Signal string  `json:"signal"`
	Value  float64 `json:"value"`
	Weight float64 `json:"weight"`
	Delta  float64 `json:"delta"` // weight * value
	Note   string  `json:"note,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTOR
// ═══════════════════════════════════════════════════════════════════════════════

// Extract computes the full feature vector for a method.
func Extract(m MethodView) Features {
	if m == nil {
		return Features{}
	}
	body := m.GetRawBody()
	calls := m.GetCalls()
	consts := m.GetStringConsts()
	insn := m.GetInstructionCount()
	if insn <= 0 {
		insn = len(body)
	}
	if insn <= 0 {
		insn = 1
	}

	cyclo := cyclomatic(body, m.GetIfCheckCount())
	nest := nestingDepth(body)
	uniqueOps, branches, returns := opcodeStats(body, m.GetReturnCount())

	secRatio, netRatio, cryRatio, dynRatio := callRatios(calls)
	obf := obfuscationScore(m.GetName(), m.GetFullSignature(), consts, body)
	nq := nameQuality(m.GetName(), m.GetFullSignature())

	taint := taintFlowScore(body, calls)

	bodyText := strings.Join(body, "\n")
	stringText := strings.Join(consts, "\n")

	return Features{
		Cyclomatic:        cyclo,
		NestingDepth:      nest,
		BranchDensity:     float64(branches) / float64(insn),
		ReturnDensity:     float64(returns) / float64(insn),
		BodyLength:        len(body),
		UniqueOpcodes:     uniqueOps,
		StringEntropy:     shannonEntropy(stringText),
		BodyEntropy:       shannonEntropy(bodyText),
		BigramEntropy:     bigramEntropy(bodyText),
		SecurityCallRatio: secRatio,
		NetworkCallRatio:  netRatio,
		CryptoCallRatio:   cryRatio,
		DynamicCallRatio:  dynRatio,
		ObfuscationScore:  obf,
		NameQualityScore:  nq,
		TaintFlowScore:    taint,
		IsAppCode:         m.GetIsAppCode(),
		IsLibrary:         m.GetIsLibrary(),
		IsCallback:        m.GetIsCallback(),
		IsConstructor:     m.GetIsConstructor(),
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORER
// ═══════════════════════════════════════════════════════════════════════════════

// Weights configures the ensemble fusion. Fields are exposed so callers can
// tune the mix without changing source. DefaultWeights mirrors the priorities
// observed in the legacy scorer plus the new structural / taint signals.
type Weights struct {
	Cyclomatic        float64
	BranchDensity     float64
	StringEntropy     float64
	BodyEntropy       float64
	SecurityCallRatio float64
	NetworkCallRatio  float64
	CryptoCallRatio   float64
	DynamicCallRatio  float64
	ObfuscationScore  float64
	NameQualityScore  float64
	TaintFlowScore    float64
	LibraryPenalty    float64
	CallbackBonus     float64
}

// DefaultWeights returns balanced ensemble weights validated on the project's
// internal corpus.
func DefaultWeights() Weights {
	return Weights{
		Cyclomatic:        4.5,
		BranchDensity:     8.0,
		StringEntropy:     3.0,
		BodyEntropy:       2.0,
		SecurityCallRatio: 18.0,
		NetworkCallRatio:  9.0,
		CryptoCallRatio:   12.0,
		DynamicCallRatio:  16.0,
		ObfuscationScore:  10.0,
		NameQualityScore:  -6.0, // higher quality lowers risk
		TaintFlowScore:    20.0,
		LibraryPenalty:    -25.0,
		CallbackBonus:     6.0,
	}
}

// Scorer produces ensemble Scores. Reuse a single Scorer across a run to
// amortize allocations; it is safe for concurrent use.
type Scorer struct {
	W Weights
}

// NewScorer builds a Scorer using DefaultWeights.
func NewScorer() *Scorer { return &Scorer{W: DefaultWeights()} }

// NewScorerWithWeights builds a Scorer with custom weights.
func NewScorerWithWeights(w Weights) *Scorer { return &Scorer{W: w} }

// Score evaluates a method and returns the blended score with explanation.
func (s *Scorer) Score(m MethodView) Score {
	f := Extract(m)
	return s.ScoreFeatures(f)
}

// ScoreFeatures evaluates a pre-computed feature vector. Useful when callers
// already cached the features (e.g., in feature stores).
func (s *Scorer) ScoreFeatures(f Features) Score {
	w := s.W
	contribs := make([]Contribution, 0, 12)

	add := func(name string, value, weight float64, note string) {
		delta := value * weight
		contribs = append(contribs, Contribution{
			Signal: name, Value: value, Weight: weight, Delta: delta, Note: note,
		})
	}

	// Normalize cyclomatic to [0..1] using log(1+x).
	cycN := math.Log1p(f.Cyclomatic) / math.Log1p(50)
	add("cyclomatic", clamp01(cycN), w.Cyclomatic, "method complexity")
	add("branch_density", clamp01(f.BranchDensity), w.BranchDensity, "if/switch density")
	add("string_entropy", clamp01(f.StringEntropy/8.0), w.StringEntropy, "string randomness")
	add("body_entropy", clamp01(f.BodyEntropy/8.0), w.BodyEntropy, "body randomness")
	add("security_calls", f.SecurityCallRatio, w.SecurityCallRatio, "security API ratio")
	add("network_calls", f.NetworkCallRatio, w.NetworkCallRatio, "network API ratio")
	add("crypto_calls", f.CryptoCallRatio, w.CryptoCallRatio, "crypto API ratio")
	add("dynamic_calls", f.DynamicCallRatio, w.DynamicCallRatio, "reflection/classloader")
	add("obfuscation", f.ObfuscationScore, w.ObfuscationScore, "obfuscation indicators")
	add("name_quality", f.NameQualityScore, w.NameQualityScore, "identifier quality")
	add("taint_flow", f.TaintFlowScore, w.TaintFlowScore, "source→sink confidence")
	if f.IsLibrary {
		add("library_penalty", 1.0, w.LibraryPenalty, "third-party library code")
	}
	if f.IsCallback {
		add("callback_bonus", 1.0, w.CallbackBonus, "android lifecycle / callback")
	}

	raw := 0.0
	for _, c := range contribs {
		raw += c.Delta
	}

	// Squash into [0..100] using a sigmoid centered at 50.
	final := 100.0 / (1.0 + math.Exp(-raw/30.0))
	if final < 0 {
		final = 0
	}
	if final > 100 {
		final = 100
	}

	conf := computeConfidence(contribs)

	// Sort contributions by absolute delta descending so the top drivers
	// surface first when explaining results.
	sort.SliceStable(contribs, func(i, j int) bool {
		return math.Abs(contribs[i].Delta) > math.Abs(contribs[j].Delta)
	})

	return Score{
		Final:         final,
		Confidence:    conf,
		Contributions: contribs,
		Features:      f,
	}
}

// computeConfidence rewards score-stability: when several signals push in the
// same direction we are more confident than when they cancel out.
func computeConfidence(c []Contribution) float64 {
	if len(c) == 0 {
		return 0
	}
	pos, neg, abs := 0.0, 0.0, 0.0
	for _, x := range c {
		if x.Delta >= 0 {
			pos += x.Delta
		} else {
			neg += -x.Delta
		}
		abs += math.Abs(x.Delta)
	}
	if abs == 0 {
		return 0
	}
	// Agreement = how lopsided the signals are.
	agree := math.Abs(pos-neg) / abs
	// Density = number of contributing signals (capped).
	density := math.Min(float64(len(c))/8.0, 1.0)
	return clamp01(0.6*agree + 0.4*density)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARALLEL SCORING
// ═══════════════════════════════════════════════════════════════════════════════

// ScoreBatch runs Score concurrently across a slice of MethodView.
//
// `workers` <= 0 picks GOMAXPROCS. Order of results matches the input order.
func (s *Scorer) ScoreBatch(methods []MethodView, workers int) []Score {
	out := make([]Score, len(methods))
	if len(methods) == 0 {
		return out
	}
	if workers <= 0 {
		workers = 4
	}
	if workers > len(methods) {
		workers = len(methods)
	}
	var wg sync.WaitGroup
	idx := make(chan int, len(methods))
	for i := range methods {
		idx <- i
	}
	close(idx)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				out[i] = s.Score(methods[i])
			}
		}()
	}
	wg.Wait()
	return out
}

// clamp01 forces a value to [0..1].
func clamp01(x float64) float64 {
	switch {
	case x < 0:
		return 0
	case x > 1:
		return 1
	default:
		return x
	}
}
