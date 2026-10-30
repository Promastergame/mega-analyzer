package shared

// SecurityCheckType represents the type of security check a method performs
type SecurityCheckType string

const (
	CheckTypeRoot     SecurityCheckType = "root_detection"
	CheckTypePremium  SecurityCheckType = "premium_check"
	CheckTypeEmulator SecurityCheckType = "emulator_detection"
	CheckTypeBilling  SecurityCheckType = "billing_verification"
	CheckTypeTamper   SecurityCheckType = "tamper_detection"
	CheckTypeDebug    SecurityCheckType = "debug_detection"
	CheckTypeUnknown  SecurityCheckType = "unknown"
)

// SignalType identifies the match channel that contributed confidence.
type SignalType string

const (
	SignalName       SignalType = "NAME"
	SignalStructure  SignalType = "STRUCTURE"
	SignalAPICall    SignalType = "API_CALL"
	SignalString     SignalType = "STRING"
	SignalReturnType SignalType = "RETURN_TYPE"
)

// MatchSignal is a single evidence item used by the scorer.
type MatchSignal struct {
	Type       SignalType `json:"type"`
	Value      string     `json:"value"`
	Weight     float64    `json:"weight"`
	Confidence float64    `json:"confidence"`
}

// RiskClass is the final risk bucket for a patch point.
type RiskClass string

const (
	RiskClassHigh   RiskClass = "HIGH"
	RiskClassMedium RiskClass = "MEDIUM"
	RiskClassLow    RiskClass = "LOW"
	RiskClassNone   RiskClass = "NONE"
)

// Emoji returns a badge for the risk class.
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

// ScoreResult is the complete scoring result for one method.
type ScoreResult struct {
	FinalScore float64   `json:"final_score"`
	RiskLevel  RiskClass `json:"risk_level"`
	Confidence float64   `json:"confidence"`

	BestPattern  *VulnerablePattern `json:"best_pattern,omitempty"`
	PatternScore float64            `json:"pattern_score"`
	AllMatches   []any              `json:"all_matches,omitempty"`

	BaseScore       float64 `json:"base_score"`
	StructuralBonus float64 `json:"structural_bonus"`
	SafePenalty     float64 `json:"safe_penalty"`
	LibraryPenalty  float64 `json:"library_penalty"`
	ContextBonus    float64 `json:"context_bonus"`
	CategoryWeight  float64 `json:"category_weight"`

	ObfuscationInfo      any     `json:"obfuscation_info,omitempty"`
	StructuralMatchScore float64 `json:"structural_match_score"`
	MatchStrategy        any     `json:"match_strategy,omitempty"`

	MatchedSignals []MatchSignal `json:"matched_signals,omitempty"`

	Reasons      []string `json:"reasons"`
	Warnings     []string `json:"warnings"`
	MatchedParts []string `json:"matched_parts"`

	SuggestedPatch PatchType     `json:"suggested_patch"`
	PatchCategory  PatchCategory `json:"patch_category"`
}

// ScoredMethod couples a parsed method with its score.
type ScoredMethod struct {
	Method    MethodInfo  `json:"method"`
	Score     ScoreResult `json:"score"`
	ClassPath string      `json:"class_path"`
	ClassName string      `json:"class_name"`
}
