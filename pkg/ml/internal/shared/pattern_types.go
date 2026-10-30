package shared

import "time"

// PatchCategory describes the security/premium check family.
type PatchCategory string

const (
	PatchCatLicense       PatchCategory = "license_check"
	PatchCatBilling       PatchCategory = "billing"
	PatchCatPremium       PatchCategory = "premium_check"
	PatchCatSubscription  PatchCategory = "subscription"
	PatchCatAds           PatchCategory = "ads"
	PatchCatRootDetect    PatchCategory = "root_detection"
	PatchCatEmulatorCheck PatchCategory = "emulator_detection"
	PatchCatDebugDetect   PatchCategory = "debug_detection"
	PatchCatTamper        PatchCategory = "tamper_detection"
	PatchCatSignature     PatchCategory = "signature_check"
	PatchCatSSLPinning    PatchCategory = "ssl_pinning"
	PatchCatIntegrity     PatchCategory = "integrity_check"
	PatchCatTrialExpiry   PatchCategory = "trial_expiry"
	PatchCatFeatureGate   PatchCategory = "feature_gate"
	PatchCatHookDetect    PatchCategory = "hook_detection"
	PatchCatInstaller     PatchCategory = "installer_check"
	PatchCatServerAuth    PatchCategory = "server_auth"
	PatchCatDRM           PatchCategory = "drm"
	PatchCatCurrency      PatchCategory = "currency"
)

// CategoryInfo describes category metadata used by reports and ranking.
type CategoryInfo struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Weight      float64 `json:"weight"`
}

// PatchType describes the patch strategy for a matched method.
type PatchType string

const (
	PatchReturnTrue   PatchType = "return_true"
	PatchReturnFalse  PatchType = "return_false"
	PatchReturnVoid   PatchType = "return_void"
	PatchReturnMaxInt PatchType = "return_max_int"
	PatchNop          PatchType = "nop"
	PatchRemoveCheck  PatchType = "remove_check"
)

// VulnerablePattern represents a patchable method pattern.
type VulnerablePattern struct {
	ID             string                `json:"id"`
	Category       PatchCategory         `json:"category"`
	Description    string                `json:"description"`
	MethodNames    []string              `json:"method_names"`
	ClassPatterns  []string              `json:"class_patterns"`
	RequiredCalls  []string              `json:"required_calls"`
	StringPatterns []string              `json:"string_patterns"`
	ReturnType     string                `json:"return_type"`
	PatchType      PatchType             `json:"patch_type"`
	Weight         float64               `json:"weight"`
	MinMatchScore  float64               `json:"min_match_score"`
	Effectiveness  *PatternEffectiveness `json:"effectiveness,omitempty"`
}

// PatternTier classifies a pattern by its observed effectiveness.
type PatternTier string

const (
	TierIMBA   PatternTier = "elite"
	TierNormal PatternTier = "normal"
	TierTrash  PatternTier = "trash"
)

// PatternEffectiveness tracks effectiveness metrics for a vulnerability pattern.
type PatternEffectiveness struct {
	PatternID string `json:"pattern_id"`

	TotalDetections int `json:"total_detections"`
	TruePositives   int `json:"true_positives"`
	FalsePositives  int `json:"false_positives"`
	CrashCount      int `json:"crash_count"`

	TruePositiveRate  float64 `json:"true_positive_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	CrashRate         float64 `json:"crash_rate"`

	Confidence float64 `json:"confidence"`
	Stability  float64 `json:"stability"`

	Tier       PatternTier `json:"tier"`
	TierReason string      `json:"tier_reason"`

	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastUpdated time.Time `json:"last_updated"`
	APKsSeenIn  int       `json:"apks_seen_in"`

	SuccessContexts map[string]int `json:"success_contexts"`
	FailureContexts map[string]int `json:"failure_contexts"`
}

// CalculateRates computes effectiveness rates from raw counts.
func (pe *PatternEffectiveness) CalculateRates() {
	total := pe.TruePositives + pe.FalsePositives

	if total > 0 {
		pe.TruePositiveRate = float64(pe.TruePositives) / float64(total)
		pe.FalsePositiveRate = float64(pe.FalsePositives) / float64(total)
	} else {
		pe.TruePositiveRate = 0.0
		pe.FalsePositiveRate = 0.0
	}

	if pe.TotalDetections > 0 {
		pe.CrashRate = float64(pe.CrashCount) / float64(pe.TotalDetections)
	} else {
		pe.CrashRate = 0.0
	}
}

const (
	MinPatchScore = 30.0

	HighRiskThreshold   = 65.0
	MediumRiskThreshold = 45.0
	LowRiskThreshold    = 30.0

	MaxHighRiskResults   = 15
	MaxMediumRiskResults = 15
	MaxLowRiskResults    = 10
)
