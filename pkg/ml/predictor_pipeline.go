package ml

import (
	"context"
	"math"
	"sort"
	"time"
)

// runPredictionPipeline is the actual PatchPredictor path, not an observability
// placeholder. No presentation MinScore cutoff precedes model/CFG/feedback
// evidence; the final threshold is applied after point enrichment.
func (pp *PatchPredictor) runPredictionPipeline(ctx context.Context, batch *BatchAnalyzeResult) ([]ScoredMethod, PipelineMetrics) {
	input := make([]ScoredMethod, 0, batch.AnalyzedMethods)
	classes := make(map[string]*ClassInfo, len(batch.Classes))
	for _, ci := range batch.Classes {
		classes[ci.FilePath+"\x00"+ci.ClassName] = ci
		for _, m := range ci.Methods {
			input = append(input, ScoredMethod{Method: m, ClassPath: ci.FilePath, ClassName: ci.ClassName})
		}
	}
	score := NewStage("score", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		out := append([]ScoredMethod(nil), in...)
		for i := range out {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			sm := &out[i]
			sm.Score = *pp.scorer.scoreMethodInClassContext(&sm.Method, classes[sm.ClassPath+"\x00"+sm.ClassName])
		}
		return out, nil
	})
	cfgStage := NewStage("cfg_evidence", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		out := cloneScoredForMutation(in)
		for start := 0; start < len(out); start += 128 {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			end := min(start+128, len(out))
			ApplyCrackPointBoost(out[start:end], pp.crackPointIndex)
		}
		return out, nil
	})
	model := NewStage("ensemble", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		if !pp.config.EnableEnsembleBoost {
			return in, nil
		}
		out := cloneScoredForMutation(in)
		for start := 0; start < len(out); start += 128 {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			end := min(start+128, len(out))
			ApplyEnsembleBoost(out[start:end], pp.config.EnsembleMix, 1, pp.trainedRiskScorer)
		}
		return out, nil
	})
	noise := NewStage("noise_and_entry", 0, pp.filterPredictorNoise)
	feedback := NewStage("user_feedback", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		if err := ctx.Err(); err != nil {
			return in, err
		}
		return pp.applyUserFeedback(cloneScoredForMutation(in)), nil
	})
	candidates := NewStage("candidate_gate", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		out := make([]ScoredMethod, 0, len(in))
		for _, sm := range in {
			if err := ctx.Err(); err != nil {
				return in, err
			}
			if math.IsNaN(sm.Score.FinalScore) || math.IsInf(sm.Score.FinalScore, 0) {
				continue
			}
			// A zero-score method can still carry independently indexed CFG evidence.
			strong, _ := pp.hasStrongPreFilterEvidence(&sm)
			if sm.Score.FinalScore > 0 || strong {
				out = append(out, sm)
			}
		}
		return out, nil
	})
	dedup := NewStage("deduplicate", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		if err := ctx.Err(); err != nil {
			return in, err
		}
		return pp.deduplicateResults(in), nil
	})
	ordered := NewStage("deterministic_score_order", 0, func(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
		out := append([]ScoredMethod(nil), in...)
		sort.Slice(out, func(i, j int) bool { return betterScoredMethod(&out[i], &out[j]) })
		return out, ctx.Err()
	})
	pp.mlPipeline = NewMLPipeline(1, score, cfgStage, model, noise, feedback, candidates, dedup, ordered)
	out, metrics := pp.mlPipeline.Run(ctx, input)
	metrics.Scope = "method_scoring_and_reranking"
	for _, stage := range metrics.Stages {
		batch.FilteredMethods += stage.Filtered
	}
	return out, metrics
}

func cloneScoredForMutation(in []ScoredMethod) []ScoredMethod {
	out := append([]ScoredMethod(nil), in...)
	for i := range out {
		out[i].Score.Reasons = append([]string(nil), in[i].Score.Reasons...)
		out[i].Score.Warnings = append([]string(nil), in[i].Score.Warnings...)
		out[i].Score.MatchedParts = append([]string(nil), in[i].Score.MatchedParts...)
	}
	return out
}
func betterScoredMethod(a, b *ScoredMethod) bool {
	as, bs := finiteRank(a.Score.FinalScore), finiteRank(b.Score.FinalScore)
	if as != bs {
		return as > bs
	}
	if a.Method.IsAppCode != b.Method.IsAppCode {
		return a.Method.IsAppCode
	}
	ac, bc := finiteRank(a.Score.Confidence), finiteRank(b.Score.Confidence)
	if ac != bc {
		return ac > bc
	}
	ak := patchLookupKey(a.ClassPath, a.Method.Name, a.Method.FullSignature) + a.ClassName
	bk := patchLookupKey(b.ClassPath, b.Method.Name, b.Method.FullSignature) + b.ClassName
	return ak < bk
}
func (pp *PatchPredictor) filterPredictorNoise(ctx context.Context, in []ScoredMethod) ([]ScoredMethod, error) {
	out := make([]ScoredMethod, 0, len(in))
	for _, sm := range cloneScoredForMutation(in) {
		if err := ctx.Err(); err != nil {
			return in, err
		}
		if pp.enableInterestingScore && pp.interestingScorer != nil {
			sm.Interesting = pp.interestingScorer.Calculate(&sm.Method, nil)
		}
		filtered := false
		if pp.enableNoiseFilter && pp.noiseFilter != nil && !(pp.config.IncludeLibraries && !sm.Method.IsAppCode) {
			filtered, _ = pp.noiseFilter.ShouldFilter(&sm.Method, sm.Interesting)
		}
		if filtered {
			if strong, reason := pp.hasStrongPreFilterEvidence(&sm); strong {
				filtered = false
				sm.Score.Reasons = append(sm.Score.Reasons, "FILTER RESCUE: "+reason)
			}
		}
		if filtered {
			continue
		}
		if pp.entryPointDetector != nil {
			sm.EntryPoint = pp.entryPointDetector.Detect(&sm.Method)
			if sm.EntryPoint != nil && pp.entryPointDetector.IsInteresting(sm.EntryPoint) {
				sm.Score.FinalScore += float64(sm.EntryPoint.Priority) * 0.1
			}
		}
		if sm.Interesting != nil && sm.Interesting.IsInteresting {
			sm.Score.FinalScore += sm.Interesting.TotalScore * 0.05
		}
		if sm.Score.FinalScore > 100 {
			sm.Score.FinalScore = 100
		}
		out = append(out, sm)
	}
	return out, nil
}

// mergePipelineMetrics combines completed batch measurements, not the mutable
// last-run metrics of a reused predictor. Throughput is reconstructed from the
// sum of measured durations and the sum of scored methods.
func mergePipelineMetrics(dst, src *PipelineMetrics) *PipelineMetrics {
	if src == nil {
		return dst
	}
	if dst == nil {
		copy := copyPipelineMetrics(*src)
		return &copy
	}
	dst.TotalMethods += src.TotalMethods
	dst.TotalDurationNs += src.TotalDurationNs
	dst.TotalDurationMs = dst.TotalDurationNs / int64(time.Millisecond)
	if dst.TotalDurationNs > 0 {
		dst.Throughput = float64(dst.TotalMethods) / (float64(dst.TotalDurationNs) / float64(time.Second))
	}
	dst.Errors = append(dst.Errors, src.Errors...)
	for _, s := range src.Stages {
		found := false
		for i := range dst.Stages {
			d := &dst.Stages[i]
			if d.Name != s.Name {
				continue
			}
			found = true
			d.InputCount += s.InputCount
			d.OutputCount += s.OutputCount
			d.Filtered += s.Filtered
			d.DurationMs += s.DurationMs
			if s.Error != "" {
				d.Error = s.Error
			}
			d.Throughput = 0
			break
		}
		if !found {
			dst.Stages = append(dst.Stages, s)
		}
	}
	return dst
}
