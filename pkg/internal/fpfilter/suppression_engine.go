package fpfilter

import (
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

// SuppressionEngine decides which findings to show and which to suppress.
type SuppressionEngine struct {
	config *config.FPFilterConfig
}

func NewSuppressionEngine(cfg *config.FPFilterConfig) *SuppressionEngine {
	if cfg == nil {
		cfg = &config.FPFilterConfig{
			Enabled:          true,
			MinScore:         0.55,
			SDKStrongSignals: true,
			NoSDKAutoIgnore:  true,
		}
	}
	return &SuppressionEngine{
		config: cfg,
	}
}

// Process filters a slice of classified findings into visible and suppressed lists,
// updating stats along the way.
func (e *SuppressionEngine) Process(findings []types.ClassifiedFinding) *types.FPFilterOutput {
	out := &types.FPFilterOutput{
		ClassifiedFindings: make([]types.ClassifiedFinding, 0),
		SuppressedFindings: make([]types.ClassifiedFinding, 0),
		Stats: types.FPFilterStats{
			TotalFindings: len(findings),
		},
	}

	for _, cf := range findings {
		// Update basic stats
		switch cf.Verdict {
		case types.VerdictConfirmedAppRisk:
			out.Stats.ConfirmedAppRisks++
		case types.VerdictConfirmedSDKRisk:
			out.Stats.ConfirmedSDKRisks++
		case types.VerdictSDKInteresting:
			out.Stats.SDKInteresting++
		case types.VerdictSDKNoiseSuppressed:
			out.Stats.SuppressedSDKNoise++
		case types.VerdictGenericNoiseSuppressed:
			out.Stats.GenericNoiseSuppressed++
		case types.VerdictNeedsContext:
			out.Stats.NeedsContext++
		case types.VerdictObservation:
			out.Stats.Observations++
		}

		if !e.config.Enabled {
			// If disabled, just put everything in classified
			out.ClassifiedFindings = append(out.ClassifiedFindings, cf)
			continue
		}

		shouldSuppress := false

		// Check strict mode
		if e.config.StrictMode {
			if cf.Verdict != types.VerdictConfirmedAppRisk && cf.Verdict != types.VerdictConfirmedSDKRisk {
				shouldSuppress = true
			}
		} else {
			// Normal mode
			if cf.Verdict == types.VerdictSDKNoiseSuppressed || cf.Verdict == types.VerdictGenericNoiseSuppressed {
				shouldSuppress = true
			}
		}

		// Also suppress if final score is below minimum. Confirmed SDK risks are
		// deliberately kept visible: third-party libraries can be vulnerable too.
		if cf.Verdict != types.VerdictConfirmedSDKRisk && cf.FinalScore < e.config.MinScore {
			shouldSuppress = true
			if cf.SuppressionReason == "" {
				cf.SuppressionReason = "Score below minimum threshold"
			}
		}

		if shouldSuppress {
			out.SuppressedFindings = append(out.SuppressedFindings, cf)
		} else {
			out.ClassifiedFindings = append(out.ClassifiedFindings, cf)
		}
	}

	// Apply limit to suppressed list unless the caller explicitly asked for the full log.
	if !e.config.ShowSuppressed && e.config.SuppressedLimit > 0 && len(out.SuppressedFindings) > e.config.SuppressedLimit {
		out.SuppressedFindings = out.SuppressedFindings[:e.config.SuppressedLimit]
	}

	// 🆕 Сбор универсальных сгруппированных паттернов (Androeed.ru, 5play.ru и др.)
	agg := NewAggregator(3)
	out.AggregatedPatterns = agg.AggregateFindings(findings)

	// Подавление избыточных повторений одинаковых паттернов из ClassifiedFindings (> 5 повторов)
	patternSeenCount := make(map[string]int)
	cleanClassified := make([]types.ClassifiedFinding, 0, len(out.ClassifiedFindings))
	for _, cf := range out.ClassifiedFindings {
		patKey := ""
		if cf.Original != nil && cf.Original.Pattern != "" {
			patKey = cf.Original.Pattern
		}
		if e.config.Enabled && patKey != "" && cf.Verdict != types.VerdictConfirmedSDKRisk && cf.Verdict != types.VerdictConfirmedAppRisk {
			patternSeenCount[patKey]++
			if patternSeenCount[patKey] > 5 {
				cf.Verdict = types.VerdictGenericNoiseSuppressed
				cf.SuppressionReason = "Redundant pattern instance aggregated"
				out.SuppressedFindings = append(out.SuppressedFindings, cf)
				continue
			}
		}
		cleanClassified = append(cleanClassified, cf)
	}
	out.ClassifiedFindings = cleanClassified

	return out
}
