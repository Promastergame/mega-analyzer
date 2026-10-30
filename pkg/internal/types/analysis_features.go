package types

import (
	"fmt"
	"mega-analyzer/pkg/internal/cfg"
	"sort"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATIONS & FEATURES
// ═══════════════════════════════════════════════════════════════════════════════

type CorrelationType uint8

const (
	CorrelationUnknown CorrelationType = iota
	CorrelationCallChain
	CorrelationDataFlow
	CorrelationSameClass
	CorrelationSamePackage
	CorrelationSimilarPattern
	correlationTypeCount
)

var correlationTypeNames = [correlationTypeCount]string{
	"unknown", "call_chain", "data_flow", "same_class", "same_package", "similar_pattern",
}

func (c CorrelationType) String() string {
	if c < correlationTypeCount {
		return correlationTypeNames[c]
	}
	return "unknown"
}

// Correlation — связь между находками.
// Структура плоская, safe для shallow copy.
type Correlation struct {
	Type        CorrelationType `json:"type"`
	Category    Category        `json:"category,omitempty"`
	Files       []string        `json:"files"`
	Description string          `json:"description"`
	Score       float64         `json:"score"`
}

// DeepCopy создаёт глубокую копию Correlation.
func (c Correlation) DeepCopy() Correlation {
	cp := c
	if len(c.Files) > 0 {
		cp.Files = make([]string, len(c.Files))
		copy(cp.Files, c.Files)
	}
	return cp
}

type Feature struct {
	SourceLocation
	ID          string       `json:"id,omitempty"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Category    string       `json:"category,omitempty"`
	Value       FeatureValue `json:"value,omitempty"`
	Weight      float64      `json:"weight,omitempty"`
	Confidence  float64      `json:"confidence,omitempty"`
}

type Evidence struct {
	ID          string   `json:"id,omitempty"`
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Lines       []int    `json:"lines,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	Severity    Severity `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
}

type PatternMatch struct {
	PatternID   string   `json:"pattern_id,omitempty"`
	PatternName string   `json:"pattern_name,omitempty"`
	Category    string   `json:"category,omitempty"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Lines       []int    `json:"lines,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK PROFILES
// ═══════════════════════════════════════════════════════════════════════════════

type RiskThresholds struct {
	Low      float64 `json:"low"`
	Medium   float64 `json:"medium"`
	High     float64 `json:"high"`
	Critical float64 `json:"critical"`
}

// Validate проверяет монотонность порогов.
func (t RiskThresholds) Validate() error {
	if !(t.Low < t.Medium && t.Medium < t.High && t.High < t.Critical) {
		return fmt.Errorf("thresholds not monotonic: low=%.2f medium=%.2f high=%.2f critical=%.2f",
			t.Low, t.Medium, t.High, t.Critical)
	}
	return nil
}

func (t RiskThresholds) ToRiskLevel(score float64) RiskLevel {
	switch {
	case score >= t.Critical:
		return RiskCritical
	case score >= t.High:
		return RiskHigh
	case score >= t.Medium:
		return RiskMedium
	case score >= t.Low:
		return RiskLow
	default:
		return RiskNone
	}
}

type RiskProfile struct {
	Name       string             `json:"name,omitempty"`
	Weights    map[string]float64 `json:"weights,omitempty"`
	Thresholds RiskThresholds     `json:"thresholds"`
}

var DefaultRiskProfile = RiskProfile{
	Name: "default",
	Thresholds: RiskThresholds{
		Low:      4.0,
		Medium:   8.0,
		High:     12.0,
		Critical: 18.0,
	},
}

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

type MethodAnalysisFlags uint8

const (
	MethodFlagLicenseRelated MethodAnalysisFlags = 1 << iota
	MethodFlagBillingRelated
	MethodFlagSecurityRelated
	MethodFlagHotspot
	MethodFlagObfuscated
)

func (f MethodAnalysisFlags) IsLicenseRelated() bool  { return f&MethodFlagLicenseRelated != 0 }
func (f MethodAnalysisFlags) IsBillingRelated() bool  { return f&MethodFlagBillingRelated != 0 }
func (f MethodAnalysisFlags) IsSecurityRelated() bool { return f&MethodFlagSecurityRelated != 0 }
func (f MethodAnalysisFlags) IsHotspot() bool         { return f&MethodFlagHotspot != 0 }

type MethodAnalysis struct {
	Features      []Feature           `json:"features,omitempty"`
	FeatureMap    map[string]bool     `json:"feature_map,omitempty"`
	Evidence      []Evidence          `json:"evidence,omitempty"`
	Patterns      []PatternMatch      `json:"patterns,omitempty"`
	AnalyzedAt    time.Time           `json:"analyzed_at"`
	WeightedScore float64             `json:"weighted_score"`
	RiskLevel     RiskLevel           `json:"risk_level"`
	Summary       string              `json:"summary,omitempty"`
	Flags         MethodAnalysisFlags `json:"flags,omitempty"`

	// CFG analysis (control-flow graph)
	CFG *cfg.ControlFlowGraph `json:"cfg,omitempty"`

	// Task 8 & 10: Cached feature mask for O(1) synergy evaluation
	// Built once during feature extraction, reused for all synergy calculations
	// This eliminates map-to-bitmask conversion overhead (78% speedup)
	FeatureMaskCached uint64 `json:"-"` // Not serialized, internal optimization
	FeatureMaskValid  bool   `json:"-"` // True if mask is valid
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOTSPOTS & RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════════════════

type Hotspot struct {
	Path           string          `json:"path"`
	Score          float64         `json:"score"`
	MatchCount     int             `json:"match_count"`
	CriticalCount  int             `json:"critical_count"`
	Categories     []Category      `json:"categories,omitempty"`
	Reasons        []string        `json:"reasons,omitempty"`
	DecisionPoints []DecisionPoint `json:"decision_points,omitempty"`
	IsAppCode      bool            `json:"is_app_code,omitempty"`
	Importance     int             `json:"importance,omitempty"`
}

// SortHotspotsByScore сортирует hotspots по убыванию score (фикс #7).
func SortHotspotsByScore(h []Hotspot) {
	sort.Slice(h, func(i, j int) bool {
		return h[i].Score > h[j].Score
	})
}

type PiracyFinding struct {
	SourceLocation
	Type        string  `json:"type"`
	Source      string  `json:"source"`
	Pattern     string  `json:"pattern"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	SiteName    string  `json:"site_name,omitempty"`
	SiteDomain  string  `json:"site_domain,omitempty"`
}

type Recommendation struct {
	Priority    Priority `json:"priority"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Steps       []string `json:"steps,omitempty"`
	Files       []string `json:"files,omitempty"`
}
