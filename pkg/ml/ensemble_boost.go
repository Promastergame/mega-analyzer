package ml

import (
	"fmt"
	"sort"
	"strings"

	"mega-analyzer/pkg/ml/ensemble"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ENSEMBLE BOOST — additive re-ranker on top of legacy patch_scorer.
// ═══════════════════════════════════════════════════════════════════════════════
//
// BoostScoredMethods consumes the legacy ScoredMethod slice produced by the
// existing pipeline and returns the same slice with two enhancements:
//
//   1. Each method receives an ensemble Score (entropy + cyclomatic + taint
//      + obfuscation + name-quality + call-ratios). The blend with the
//      legacy score is configurable via BoostMix.
//   2. The slice is re-sorted by the blended score descending, with stable
//      tie-breaks on the original ordering.
//
// The legacy ScoreResult is left intact so callers downstream that rely on
// it still work; the ensemble result is exposed as the new BoostScore field
// (added below) and surfaces in the explanation outputs.

// BoostMix controls how the legacy and ensemble scores are blended.
type BoostMix struct {
	// LegacyWeight is the weight given to the legacy ScoreResult.Score (0..100).
	LegacyWeight float64
	// EnsembleWeight is the weight given to the ensemble Score.Final (0..100).
	EnsembleWeight float64
	// MinConfidence drops methods whose ensemble confidence is below this.
	MinConfidence float64
}

// DefaultBoostMix returns a balanced blend that nudges the existing scoring
// without overpowering it.
func DefaultBoostMix() BoostMix {
	return BoostMix{LegacyWeight: 0.55, EnsembleWeight: 0.45, MinConfidence: 0.0}
}

// Validate performs validation on the BoostMix and returns an error if invalid.
func (bm *BoostMix) Validate() error {
	if bm.LegacyWeight < 0 || bm.LegacyWeight > 1 {
		return fmt.Errorf("LegacyWeight must be between 0 and 1, got %f", bm.LegacyWeight)
	}
	if bm.EnsembleWeight < 0 || bm.EnsembleWeight > 1 {
		return fmt.Errorf("EnsembleWeight must be between 0 and 1, got %f", bm.EnsembleWeight)
	}
	if bm.MinConfidence < 0 || bm.MinConfidence > 1 {
		return fmt.Errorf("MinConfidence must be between 0 and 1, got %f", bm.MinConfidence)
	}
	// Check that weights sum to approximately 1 (allowing for small floating point errors)
	totalWeight := bm.LegacyWeight + bm.EnsembleWeight
	if totalWeight < 0.9 || totalWeight > 1.1 {
		return fmt.Errorf("LegacyWeight + EnsembleWeight must sum to approximately 1, got %f", totalWeight)
	}
	return nil
}

// methodInfoView adapts MethodInfo to the ensemble.MethodView contract.
type methodInfoView struct{ m *MethodInfo }

func (v methodInfoView) GetName() string           { return v.m.Name }
func (v methodInfoView) GetFullSignature() string  { return v.m.FullSignature }
func (v methodInfoView) GetReturnType() string     { return v.m.ReturnType }
func (v methodInfoView) GetInstructionCount() int  { return v.m.InstructionCount }
func (v methodInfoView) GetRegisterCount() int     { return v.m.RegisterCount }
func (v methodInfoView) GetIfCheckCount() int      { return v.m.IfCheckCount }
func (v methodInfoView) GetReturnCount() int       { return v.m.ReturnCount }
func (v methodInfoView) GetStringConsts() []string { return v.m.StringConsts }
func (v methodInfoView) GetRawBody() []string      { return v.m.RawBody }
func (v methodInfoView) GetIsAppCode() bool        { return v.m.IsAppCode }
func (v methodInfoView) GetIsLibrary() bool        { return v.m.IsLibrary }
func (v methodInfoView) GetIsCallback() bool       { return v.m.IsCallback }
func (v methodInfoView) GetIsConstructor() bool    { return v.m.IsConstructor }

func (v methodInfoView) GetCalls() []string {
	if v.m == nil {
		return nil
	}
	out := make([]string, 0, len(v.m.Calls))
	for _, c := range v.m.Calls {
		if c.FullCall != "" {
			out = append(out, c.FullCall)
			continue
		}
		out = append(out, c.Class+"->"+c.Method)
	}
	// Plus any raw security calls captured separately.
	out = append(out, v.m.SecurityCalls...)
	return out
}

// BoostedScoredMethod augments ScoredMethod with ensemble output.
type BoostedScoredMethod struct {
	ScoredMethod
	Ensemble    ensemble.Score `json:"ensemble"`
	BoostScore  float64        `json:"boost_score"`
	Explanation string         `json:"boost_explanation,omitempty"`
}

// TrainedRiskScorer is the injection seam for a learned model that refines the
// ensemble's hand-tuned heuristic blend. Implementations (e.g.
// training.EnsembleModelScorer) must never panic and must report
// IsLoaded()==false when no trained model backs them yet, so callers can treat
// a missing model as a pure no-op instead of special-casing it.
type TrainedRiskScorer interface {
	IsLoaded() bool
	Score(f ensemble.Features) (prob float64, ok bool)
}

// ApplyEnsembleBoost blends each ScoredMethod's legacy heuristic score with the
// ensemble package's structural/entropy/taint signal blend, mutating
// sm.Score.FinalScore in place — the same style as ApplyCrackPointBoost — so
// every downstream consumer of FinalScore (dedup, min-score filtering,
// scoredMethodToPoint's risk classification) picks up the blended score
// without any further plumbing. Input slice is mutated and returned.
//
// The full ensemble.Score (with per-signal Contributions) is kept on
// sm.Ensemble for explanation surfaces; it is not part of ScoreResult's JSON
// contract.
//
// `trained`, when non-nil and IsLoaded(), blends its calibrated probability
// into the ensemble component. A nil or unloaded scorer leaves behavior
// identical to the heuristic-only ensemble.DefaultWeights() blend — this is
// the common case until a model has been trained from accumulated feedback.
//
// `workers` controls parallelism (<=0 picks 4, mirrors ensemble.ScoreBatch).
func ApplyEnsembleBoost(scored []ScoredMethod, mix BoostMix, workers int, trained TrainedRiskScorer) []ScoredMethod {
	if len(scored) == 0 {
		return scored
	}
	if mix.LegacyWeight == 0 && mix.EnsembleWeight == 0 {
		mix = DefaultBoostMix()
	}

	scorer := ensemble.NewScorer()
	views := make([]ensemble.MethodView, len(scored))
	for i := range scored {
		views[i] = methodInfoView{m: &scored[i].Method}
	}
	scores := scorer.ScoreBatch(views, workers)

	for i := range scored {
		ens := scores[i]
		if trained != nil && trained.IsLoaded() {
			if prob, ok := trained.Score(ens.Features); ok {
				learned := prob * 100.0
				// Average the heuristic ensemble score with the learned
				// model's calibrated probability — neither fully overrides
				// the other until the learned model has proven itself.
				ens.Final = (ens.Final + learned) / 2.0
			}
		}
		scored[i].Ensemble = &ens

		legacy := scored[i].Score.FinalScore
		blended := blendScores(legacy, ens.Final, mix)
		if blended > 100 {
			blended = 100
		}
		if blended < 0 {
			blended = 0
		}
		explanation := explainBoost(scored[i], ens, mix, blended)
		scored[i].Score.FinalScore = blended
		scored[i].Score.Reasons = append(scored[i].Score.Reasons, explanation)
	}

	return scored
}

// BoostScoredMethods runs the ensemble on each ScoredMethod and returns a new
// slice ordered by the blended score. Input is not mutated.
//
// `workers` controls parallelism (<=0 picks 4).
func BoostScoredMethods(in []ScoredMethod, mix BoostMix, workers int) []BoostedScoredMethod {
	if len(in) == 0 {
		return nil
	}
	scorer := ensemble.NewScorer()

	views := make([]ensemble.MethodView, len(in))
	for i := range in {
		views[i] = methodInfoView{m: &in[i].Method}
	}
	scores := scorer.ScoreBatch(views, workers)

	out := make([]BoostedScoredMethod, 0, len(in))
	for i, sm := range in {
		ens := scores[i]
		if ens.Confidence < mix.MinConfidence {
			continue
		}
		blend := blendScores(sm.Score.FinalScore, ens.Final, mix)
		bs := BoostedScoredMethod{
			ScoredMethod: sm,
			Ensemble:     ens,
			BoostScore:   blend,
			Explanation:  explainBoost(sm, ens, mix, blend),
		}
		out = append(out, bs)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].BoostScore != out[j].BoostScore {
			return out[i].BoostScore > out[j].BoostScore
		}
		return out[i].Score.FinalScore > out[j].Score.FinalScore
	})

	return out
}

// blendScores combines legacy and ensemble scores using BoostMix weights.
func blendScores(legacy, ens float64, mix BoostMix) float64 {
	wL := mix.LegacyWeight
	wE := mix.EnsembleWeight
	total := wL + wE
	if total <= 0 {
		return legacy
	}
	return (legacy*wL + ens*wE) / total
}

// explainBoost produces a short, human-readable explanation of the blend.
func explainBoost(sm ScoredMethod, ens ensemble.Score, mix BoostMix, blend float64) string {
	var b strings.Builder
	b.Grow(256)
	b.WriteString("blend ")
	writeFloat(&b, blend)
	b.WriteString(" = legacy(")
	writeFloat(&b, sm.Score.FinalScore)
	b.WriteString(")×")
	writeFloat(&b, mix.LegacyWeight)
	b.WriteString(" + ensemble(")
	writeFloat(&b, ens.Final)
	b.WriteString(")×")
	writeFloat(&b, mix.EnsembleWeight)
	if len(ens.Contributions) > 0 {
		b.WriteString(" — top: ")
		topN := 3
		if len(ens.Contributions) < topN {
			topN = len(ens.Contributions)
		}
		for i := 0; i < topN; i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(ens.Contributions[i].Signal)
			b.WriteString("=")
			writeFloat(&b, ens.Contributions[i].Delta)
		}
	}
	return b.String()
}

func writeFloat(b *strings.Builder, v float64) {
	const digits = "0123456789"
	if v < 0 {
		b.WriteByte('-')
		v = -v
	}
	intPart := int64(v)
	fracPart := int64((v - float64(intPart)) * 100)
	if fracPart < 0 {
		fracPart = -fracPart
	}
	if intPart == 0 {
		b.WriteByte('0')
	} else {
		// Cheap int -> string.
		var buf [20]byte
		i := len(buf)
		for intPart > 0 {
			i--
			buf[i] = digits[intPart%10]
			intPart /= 10
		}
		b.Write(buf[i:])
	}
	b.WriteByte('.')
	if fracPart < 10 {
		b.WriteByte('0')
	}
	b.WriteByte(digits[fracPart/10])
	b.WriteByte(digits[fracPart%10])
}
