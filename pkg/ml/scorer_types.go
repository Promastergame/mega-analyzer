package ml

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH SCORER — считает risk score для каждого метода
//
// Scoring pipeline:
//   1. Match vulnerable patterns → base score
//   2. Apply structural bonuses → +points
//   3. Apply safe pattern penalties → -points
//   4. Apply library penalty → -points
//   5. Apply context bonuses → +points
//   6. Normalize to 0-100 → final score
//   7. Classify risk level → high/medium/low
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH SIGNAL (Task 13.1)
// ═══════════════════════════════════════════════════════════════════════════════

// SignalType represents the type of matching signal
type SignalType string

const (
	SignalName       SignalType = "NAME"
	SignalStructure  SignalType = "STRUCTURE"
	SignalAPICall    SignalType = "API_CALL"
	SignalString     SignalType = "STRING"
	SignalReturnType SignalType = "RETURN_TYPE"
	SignalVulnSignal SignalType = "VULN_SIGNAL"
)

// SignalWeights defines the weight for each signal type in confidence calculation
// Higher weights indicate more reliable signals for vulnerability detection
var SignalWeights = map[SignalType]float64{
	SignalName:       1.0, // Method name match
	SignalStructure:  0.9, // Structural patterns
	SignalAPICall:    1.1, // API call match (highest weight)
	SignalString:     0.8, // String constant match
	SignalReturnType: 0.7, // Return type match
	SignalVulnSignal: 1.3, // Confirmed audit/vulnerability signal
}

// MatchSignal represents a single matching indicator
type MatchSignal struct {
	Type       SignalType `json:"type"`
	Value      string     `json:"value"`
	Weight     float64    `json:"weight"`
	Confidence float64    `json:"confidence"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE RESULT
// ═══════════════════════════════════════════════════════════════════════════════

// ScoreResult — полный результат скоринга одного метода
type ScoreResult struct {
	// ── Итоговый score ────────────────────────────────────────────
	FinalScore float64   `json:"final_score"` // 0-100
	RiskLevel  RiskClass `json:"risk_level"`  // high/medium/low/none
	Confidence float64   `json:"confidence"`  // 0-1 (насколько уверены)

	// ── Matched pattern ──────────────────────────────────────────
	BestPattern  *VulnerablePattern `json:"best_pattern,omitempty"`
	PatternScore float64            `json:"pattern_score"`
	AllMatches   []PatternMatch     `json:"all_matches,omitempty"`

	// ── Breakdown ────────────────────────────────────────────────
	BaseScore       float64 `json:"base_score"`
	StructuralBonus float64 `json:"structural_bonus"`
	SafePenalty     float64 `json:"safe_penalty"`
	LibraryPenalty  float64 `json:"library_penalty"`
	ContextBonus    float64 `json:"context_bonus"`
	CategoryWeight  float64 `json:"category_weight"`

	// ── Obfuscation info (Task 12) ───────────────────────────────
	ObfuscationInfo      *ObfuscationInfo `json:"obfuscation_info,omitempty"`
	StructuralMatchScore float64          `json:"structural_match_score"`
	MatchStrategy        MatchStrategy    `json:"match_strategy,omitempty"`

	// ── Multi-signal confidence (Task 13.1) ──────────────────────
	MatchedSignals      []MatchSignal        `json:"matched_signals,omitempty"`
	ConfidenceBreakdown *ConfidenceBreakdown `json:"confidence_breakdown,omitempty"`

	// ── Детали ───────────────────────────────────────────────────
	Reasons      []string `json:"reasons"`       // почему уязвим
	Warnings     []string `json:"warnings"`      // предупреждения
	MatchedParts []string `json:"matched_parts"` // что совпало

	// ── Patch info ───────────────────────────────────────────────
	SuggestedPatch PatchType     `json:"suggested_patch"`
	PatchCategory  PatchCategory `json:"patch_category"`

	// Optional runtime ML signals. They remain zero/nil when no model is configured.
	AnomalyScore         float64               `json:"anomaly_score,omitempty"`
	RuntimeConfidence    *RuntimeConfidence    `json:"runtime_confidence,omitempty"`
	VulnerabilitySignals *VulnerabilitySignals `json:"vulnerability_signals,omitempty"`
}

// RiskClass — уровень риска
type RiskClass string

const (
	RiskClassHigh   RiskClass = "HIGH"
	RiskClassMedium RiskClass = "MEDIUM"
	RiskClassLow    RiskClass = "LOW"
	RiskClassNone   RiskClass = "NONE"
)

// RiskEmoji возвращает эмодзи для уровня риска
func (r RiskClass) Emoji() string {
	switch r {
	case RiskClassHigh:
		return "🔴"
	case RiskClassMedium:
		return "🟡"
	case RiskClassLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// RiskLevelFromScore mapps a numeric score to RiskClass using package-level
// thresholds (HighRiskThreshold/MediumRiskThreshold/LowRiskThreshold).
// Single source of truth for tier classification — used by PatchScorer when
// computing the initial level and by PatchPredictor when re-classifying after
// DFG/PatchValue bonuses are applied (Phase 1+).
func RiskLevelFromScore(score float64) RiskClass {
	switch {
	case score >= HighRiskThreshold:
		return RiskClassHigh
	case score >= MediumRiskThreshold:
		return RiskClassMedium
	case score >= LowRiskThreshold:
		return RiskClassLow
	default:
		return RiskClassNone
	}
}
