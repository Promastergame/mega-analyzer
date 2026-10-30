package fpfilter

import (
	"strings"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/filter"
	"mega-analyzer/pkg/internal/types"
)

// Classifier orchestrates the FP filtering process.
type Classifier struct {
	config          *config.FPFilterConfig
	sdkDetector     *SDKDetector
	sigDetector     *StrongSignalDetector
	bpDetector      *BoilerplateDetector
	secretValidator *SecretValidator
}

func NewClassifier(cfg *config.FPFilterConfig, f *filter.Filter) *Classifier {
	if cfg == nil {
		cfg = &config.FPFilterConfig{
			Enabled:          true,
			MinScore:         0.55,
			SDKStrongSignals: true,
			NoSDKAutoIgnore:  true,
		}
	}
	return &Classifier{
		config:          cfg,
		sdkDetector:     NewSDKDetector(f),
		sigDetector:     NewStrongSignalDetector(),
		bpDetector:      NewBoilerplateDetector(),
		secretValidator: NewSecretValidator(),
	}
}

// Classify processes a single finding and assigns a verdict and final score.
func (c *Classifier) Classify(match *types.Match, filePath string) types.ClassifiedFinding {
	if match == nil {
		return types.ClassifiedFinding{
			Verdict: types.VerdictNeedsContext,
		}
	}

	cf := types.ClassifiedFinding{
		Original:      match,
		OriginalScore: match.Score,
		FinalScore:    match.Score,
		ScoreBreakdown: types.ScoreBreakdown{
			BaseScore: match.Score,
		},
	}

	// 1. Detect SDK Origin
	cf.SDKInfo = c.sdkDetector.Detect(match, filePath)

	// 2. Detect Strong Signals
	cf.StrongSignals = c.sigDetector.Detect(match)

	// 2b. Validate secret-style findings with entropy + format heuristics.
	// This rescales (or removes) the hardcoded_secret signal so that
	// low-entropy placeholders no longer count as strong signals, while
	// real high-entropy / known-format credentials are boosted.
	if isSecretCategory(match.Category) {
		sv := c.secretValidator.Validate(match)
		filtered := cf.StrongSignals[:0]
		for _, sig := range cf.StrongSignals {
			if sig.SignalType != "hardcoded_secret" {
				filtered = append(filtered, sig)
				continue
			}
			if sv.IsReal {
				sig.Confidence = sv.Confidence
				sig.Evidence = sv.Reason
				filtered = append(filtered, sig)
			} else {
				// Drop the strong signal; record why it was suppressed.
				if cf.SuppressionReason == "" {
					cf.SuppressionReason = "secret-like finding rejected: " + sv.Reason
				}
			}
		}
		cf.StrongSignals = filtered
	}

	// Calculate Strong Signal Score
	for _, sig := range cf.StrongSignals {
		bonus := sig.Confidence * 20.0
		cf.ScoreBreakdown.StrongSignalScore += bonus
	}
	cf.FinalScore += cf.ScoreBreakdown.StrongSignalScore

	// 3. Check Boilerplate
	isBP, bpReason := c.bpDetector.IsBoilerplate(match, cf.SDKInfo)
	if isBP {
		penalty := 10.0
		cf.ScoreBreakdown.CommonBoilerplateScore -= penalty
		cf.FinalScore += cf.ScoreBreakdown.CommonBoilerplateScore
		if cf.SuppressionReason == "" {
			cf.SuppressionReason = bpReason
		}
	}

	// Apply generic SDK noise penalty ONLY IF there are no strong signals
	if cf.SDKInfo != nil && len(cf.StrongSignals) == 0 {
		penalty := 15.0
		cf.ScoreBreakdown.GenericSDKNoiseScore -= penalty
		cf.FinalScore += cf.ScoreBreakdown.GenericSDKNoiseScore
		if cf.SuppressionReason == "" {
			cf.SuppressionReason = "Generic SDK boilerplate without strong security signals"
		}
	}

	// Ensure score doesn't drop below 0
	if cf.FinalScore < 0 {
		cf.FinalScore = 0
	}

	// 4. Assign Verdict
	cf.Verdict = c.assignVerdict(&cf)

	return cf
}

func (c *Classifier) assignVerdict(cf *types.ClassifiedFinding) types.Verdict {
	orig := cf.Original
	if orig != nil {
		fileLower := strings.ToLower(orig.File)
		// 🖼️ PNG / Media Entropy False Positive Filter
		if strings.HasSuffix(fileLower, ".png") || strings.HasSuffix(fileLower, ".jpg") ||
			strings.HasSuffix(fileLower, ".jpeg") || strings.HasSuffix(fileLower, ".webp") ||
			strings.HasSuffix(fileLower, ".mp3") || strings.HasSuffix(fileLower, ".ogg") {
			if orig.Category == "malware" || strings.Contains(orig.Pattern, "HighEntropy") || strings.Contains(orig.Text, "HighEntropy") {
				cf.SuppressionReason = "Compressed image/media file natural entropy noise (non-executable asset)"
				return types.VerdictGenericNoiseSuppressed
			}
		}
	}

	hasStrongSignals := len(cf.StrongSignals) > 0
	isSDK := cf.SDKInfo != nil

	if isSDK {
		if hasStrongSignals {
			return types.VerdictConfirmedSDKRisk
		}
		if cf.FinalScore > 10.0 {
			return types.VerdictSDKInteresting
		}
		return types.VerdictSDKNoiseSuppressed
	}

	// App code
	if hasStrongSignals || cf.FinalScore > 15.0 {
		return types.VerdictConfirmedAppRisk
	}

	if cf.ScoreBreakdown.CommonBoilerplateScore < 0 {
		return types.VerdictGenericNoiseSuppressed
	}

	return types.VerdictNeedsContext
}
