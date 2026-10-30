// Package piracy — scoring_engine_test.go
package piracy

import (
	"math"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func finding(typ string, conf, weight float64, strength SignalStrength, tags ...string) Finding {
	return Finding{
		Type:       typ,
		Confidence: conf,
		Weight:     weight,
		Strength:   strength,
		Pattern:    typ + "_pattern",
		RiskTags:   tags,
	}
}

func approxEq(a, b, eps float64) bool {
	return math.Abs(a-b) < eps
}

// ═══════════════════════════════════════════════════════════════════════════════
// FINDINGS → EVIDENCE MAPPING
// ═══════════════════════════════════════════════════════════════════════════════

func TestFindingsToEvidence_MapsAndInfers(t *testing.T) {
	se := NewScoringEngine()

	f := Finding{
		Type:        "path",
		Source:      "src",
		Pattern:     "pat",
		Location:    "loc",
		Confidence:  0.8,
		Weight:      0.7,
		Description: "desc",
		Strength:    SignalStrength("invalid"),
		RiskTags:    []string{"malware"},
	}

	evidence := se.findingsToEvidence([]Finding{f})
	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidence))
	}

	ev := evidence[0]
	if ev.Type != SignalSource {
		t.Errorf("Type = %q, want %q", ev.Type, SignalSource)
	}
	if ev.Strength != StrengthCritical {
		t.Errorf("Strength = %q, want %q", ev.Strength, StrengthCritical)
	}
	if ev.Source != f.Source || ev.Pattern != f.Pattern || ev.Location != f.Location ||
		ev.Description != f.Description || ev.Confidence != f.Confidence || ev.Weight != f.Weight {
		t.Errorf("evidence fields not mapped correctly: %+v", ev)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABLE TESTS: RISK LEVELS
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetRiskLevel(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name       string
		confidence float64
		want       RiskLevel
	}{
		{"zero", 0.0, RiskMinimal},
		{"low boundary", 0.3, RiskLow},
		{"just below medium", 0.49, RiskLow},
		{"medium boundary", 0.5, RiskMedium},
		{"high boundary", 0.7, RiskHigh},
		{"critical boundary", 0.9, RiskCritical},
		{"max", 1.0, RiskCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := se.getRiskLevel(tt.confidence)
			if got != tt.want {
				t.Errorf("getRiskLevel(%f) = %q, want %q", tt.confidence, got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABLE TESTS: EMPTY / SINGLE / MULTIPLE FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateScore_EmptyFindings(t *testing.T) {
	se := NewScoringEngine()
	result := se.CalculateScore(nil)

	if result.FinalConfidence != 0 {
		t.Errorf("expected 0 confidence for empty findings, got %f", result.FinalConfidence)
	}
	if result.RiskLevel != RiskNone {
		t.Errorf("expected risk 'none', got %q", result.RiskLevel)
	}
	if result.SignalBreakdown == nil || len(result.SignalBreakdown) != 0 {
		t.Errorf("expected empty signal breakdown map, got %#v", result.SignalBreakdown)
	}
}

func TestCalculateScore_SingleFinding(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name     string
		finding  Finding
		minConf  float64
		maxConf  float64
		wantRisk RiskLevel
	}{
		{
			name:     "single weak behavior",
			finding:  finding("mod", 0.3, 1.0, StrengthWeak),
			minConf:  0.05,
			maxConf:  0.30,
			wantRisk: RiskMinimal,
		},
		{
			name:     "single critical malware",
			finding:  finding("malware", 0.95, 1.0, StrengthCritical),
			minConf:  0.50,
			maxConf:  1.0,
			wantRisk: RiskHigh, // boosted by malware+any? only if there's another type
		},
		{
			name:     "single medium watermark",
			finding:  finding("watermark", 0.7, 1.0, StrengthMedium),
			minConf:  0.20,
			maxConf:  0.60,
			wantRisk: RiskLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := se.CalculateScore([]Finding{tt.finding})
			if result.FinalConfidence < tt.minConf || result.FinalConfidence > tt.maxConf {
				t.Errorf("confidence %f not in [%f, %f]",
					result.FinalConfidence, tt.minConf, tt.maxConf)
			}
			if tt.wantRisk != "" && result.RiskLevel != tt.wantRisk {
				t.Errorf("risk level = %q, want %q", result.RiskLevel, tt.wantRisk)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABLE TESTS: COMBINATION BOOSTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCombinationBoosts(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name     string
		findings []Finding
		minBoost float64
		maxBoost float64
	}{
		{
			name: "watermark+crack → 1.3x",
			findings: []Finding{
				finding("watermark", 0.8, 1.0, StrengthMedium),
				finding("crack", 0.8, 1.0, StrengthStrong),
			},
			minBoost: 1.29,
			maxBoost: 1.31,
		},
		{
			name: "crack_tool+behavior → 1.25x",
			findings: []Finding{
				finding("crack_tool", 0.9, 1.0, StrengthCritical),
				finding("mod", 0.5, 1.0, StrengthWeak),
			},
			minBoost: 1.24,
			maxBoost: 1.26,
		},
		{
			name: "malware+any → 1.5x (with behavior)",
			findings: []Finding{
				finding("malware", 0.9, 1.0, StrengthCritical),
				finding("mod", 0.3, 1.0, StrengthWeak),
			},
			minBoost: 1.49,
			maxBoost: 2.0, // may stack with multiple_critical
		},
		{
			name: "no combo → 1.0x",
			findings: []Finding{
				finding("mod", 0.5, 1.0, StrengthWeak),
				finding("mod", 0.4, 1.0, StrengthWeak),
			},
			minBoost: 1.0,
			maxBoost: 1.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := se.findingsToEvidence(tt.findings)
			groups := groupBySignal(evidence)
			boost := se.calculateCombinationBoost(groups)

			if boost < tt.minBoost || boost > tt.maxBoost {
				t.Errorf("boost %f not in [%f, %f]", boost, tt.minBoost, tt.maxBoost)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABLE TESTS: MULTIPLE CRITICAL THRESHOLD
// ═══════════════════════════════════════════════════════════════════════════════

func TestMultipleCriticalBoost(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name          string
		findings      []Finding
		wantCritBoost bool
	}{
		{
			name: "2 critical signals → boost",
			findings: []Finding{
				finding("malware", 0.9, 1.0, StrengthCritical),
				finding("crack_tool", 0.8, 1.0, StrengthCritical),
			},
			wantCritBoost: true,
		},
		{
			name: "1 critical signal → no boost",
			findings: []Finding{
				finding("malware", 0.9, 1.0, StrengthCritical),
				finding("mod", 0.5, 1.0, StrengthWeak),
			},
			wantCritBoost: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := se.findingsToEvidence(tt.findings)
			groups := groupBySignal(evidence)
			boost := se.calculateCombinationBoost(groups)

			critMult := se.cfg.CombinationBoosts[ComboMultipleCritical]
			// Check if boost includes the critical multiplier
			// (boost is product of all matching combos)
			if tt.wantCritBoost && boost < critMult {
				t.Errorf("expected critical boost (>= %f), got %f", critMult, boost)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TABLE TESTS: DUPLICATE DECAY
// ═══════════════════════════════════════════════════════════════════════════════

func TestDuplicateDecay(t *testing.T) {
	se := NewScoringEngine()

	// 5 identical weak signals should score less than 5x a single one
	single := []Finding{finding("mod", 0.5, 1.0, StrengthWeak)}
	five := []Finding{
		finding("mod", 0.5, 1.0, StrengthWeak),
		finding("mod", 0.5, 1.0, StrengthWeak),
		finding("mod", 0.5, 1.0, StrengthWeak),
		finding("mod", 0.5, 1.0, StrengthWeak),
		finding("mod", 0.5, 1.0, StrengthWeak),
	}

	singleResult := se.CalculateScore(single)
	fiveResult := se.CalculateScore(five)

	// Five duplicates should be higher than single (diversity factor)
	// but not 5x higher due to decay
	if fiveResult.FinalConfidence >= singleResult.FinalConfidence*3 {
		t.Errorf(
			"duplicate decay not working: single=%f, five=%f (ratio=%.1fx)",
			singleResult.FinalConfidence, fiveResult.FinalConfidence,
			fiveResult.FinalConfidence/singleResult.FinalConfidence,
		)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE CONFIDENCE — ДЕТЕРМИНИРОВАННЫЕ ПРОВЕРКИ
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateBaseConfidence_MaxOnly(t *testing.T) {
	cfg := DefaultScoringConfig()
	for _, s := range AllStrengths {
		cfg.SignalWeights[s] = 1.0
	}
	cfg.BlendMax = 1.0
	cfg.BlendAvg = 0.0
	cfg.BlendDiversity = 0.0
	cfg.DuplicateDecay = 1.0
	cfg.DiversityCap = 10.0

	se, err := NewScoringEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	findings := []Finding{
		finding("crack", 0.6, 1.0, StrengthStrong), // effective 0.6
		finding("mod", 0.8, 0.5, StrengthWeak),     // effective 0.4
	}

	evidence := se.findingsToEvidence(findings)
	groups := groupBySignal(evidence)
	base := se.calculateBaseConfidence(evidence, groups)

	if !approxEq(base, 0.6, 1e-6) {
		t.Errorf("base confidence = %f, want 0.6", base)
	}
}

func TestCalculateBaseConfidence_DiversityOnly(t *testing.T) {
	cfg := DefaultScoringConfig()
	for _, s := range AllStrengths {
		cfg.SignalWeights[s] = 1.0
	}
	cfg.BlendMax = 0.0
	cfg.BlendAvg = 0.0
	cfg.BlendDiversity = 1.0
	cfg.DiversityCap = 4.0
	cfg.DuplicateDecay = 1.0

	se, err := NewScoringEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	findings := []Finding{
		finding("crack", 0.1, 1.0, StrengthStrong),
		finding("mod", 0.9, 1.0, StrengthWeak),
	}

	evidence := se.findingsToEvidence(findings)
	groups := groupBySignal(evidence)
	base := se.calculateBaseConfidence(evidence, groups)

	if !approxEq(base, 0.5, 1e-6) {
		t.Errorf("base confidence = %f, want 0.5", base)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ScoringConfig)
		wantErr bool
	}{
		{
			name:    "default is valid",
			mutate:  func(c *ScoringConfig) {},
			wantErr: false,
		},
		{
			name: "missing strength weight",
			mutate: func(c *ScoringConfig) {
				delete(c.SignalWeights, StrengthCritical)
			},
			wantErr: true,
		},
		{
			name: "negative weight",
			mutate: func(c *ScoringConfig) {
				c.SignalWeights[StrengthWeak] = -0.5
			},
			wantErr: true,
		},
		{
			name: "boost below 1.0",
			mutate: func(c *ScoringConfig) {
				c.CombinationBoosts[ComboMalwareAny] = 0.5
			},
			wantErr: true,
		},
		{
			name: "max_boost below 1.0",
			mutate: func(c *ScoringConfig) {
				c.MaxBoost = 0.8
			},
			wantErr: true,
		},
		{
			name: "bad blend sum",
			mutate: func(c *ScoringConfig) {
				c.BlendMax = 0.9
				// sum = 0.9 + 0.3 + 0.1 = 1.3
			},
			wantErr: true,
		},
		{
			name: "bad decay",
			mutate: func(c *ScoringConfig) {
				c.DuplicateDecay = 0
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScoringConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL TYPE / STRENGTH VALIDITY
// ═══════════════════════════════════════════════════════════════════════════════

func TestSignalTypeValid(t *testing.T) {
	if !SignalMalware.Valid() {
		t.Error("SignalMalware should be valid")
	}
	if SignalType("banana").Valid() {
		t.Error("'banana' should not be a valid SignalType")
	}
}

func TestStrengthValid(t *testing.T) {
	if !StrengthCritical.Valid() {
		t.Error("StrengthCritical should be valid")
	}
	if SignalStrength("mega").Valid() {
		t.Error("'mega' should not be a valid strength")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INFERENCE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestInferStrength(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name string
		f    Finding
		want SignalStrength
	}{
		{
			name: "explicit strength preserved",
			f:    Finding{Type: "mod", Strength: StrengthStrong},
			want: StrengthStrong,
		},
		{
			name: "malware tag overrides type",
			f:    Finding{Type: "mod", RiskTags: []string{"malware"}},
			want: StrengthCritical,
		},
		{
			name: "crack type → strong",
			f:    Finding{Type: "crack"},
			want: StrengthStrong,
		},
		{
			name: "unknown type → minimal",
			f:    Finding{Type: "???"},
			want: StrengthWeak, // maps to behavior → weak
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := se.inferStrength(tt.f)
			if got != tt.want {
				t.Errorf("inferStrength() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBO MATCHING — WILDCARD И ТОЧНЫЕ ПАРЫ
// ═══════════════════════════════════════════════════════════════════════════════

func TestComboMatches_WildcardAndExact(t *testing.T) {
	se := NewScoringEngine()

	// Wildcard: malware + any other type
	groups := map[SignalType][]Evidence{
		SignalMalware: {{Type: SignalMalware}},
	}
	if se.comboMatches(ComboMalwareAny, groups) {
		t.Error("expected wildcard combo to be false with only malware present")
	}
	groups[SignalBehavior] = []Evidence{{Type: SignalBehavior}}
	if !se.comboMatches(ComboMalwareAny, groups) {
		t.Error("expected wildcard combo to be true when another type exists")
	}

	// Exact: watermark + crack
	groups = map[SignalType][]Evidence{
		SignalWatermark: {{Type: SignalWatermark}},
	}
	if se.comboMatches(ComboWatermarkCrack, groups) {
		t.Error("expected exact combo to be false without crack")
	}
	groups[SignalCrack] = []Evidence{{Type: SignalCrack}}
	if !se.comboMatches(ComboWatermarkCrack, groups) {
		t.Error("expected exact combo to be true with both types present")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// END-TO-END: REALISTIC SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

func TestEndToEnd_HighConfidencePiracy(t *testing.T) {
	se := NewScoringEngine()

	findings := []Finding{
		finding("watermark", 0.9, 1.0, StrengthMedium),
		finding("crack", 0.85, 1.0, StrengthStrong),
		finding("crack_tool", 0.8, 1.0, StrengthCritical),
		finding("site", 0.7, 0.8, StrengthMedium),
	}

	result := se.CalculateScore(findings)

	if result.FinalConfidence < 0.7 {
		t.Errorf("expected high confidence for clear piracy, got %f", result.FinalConfidence)
	}
	if result.RiskLevel != RiskHigh && result.RiskLevel != RiskCritical {
		t.Errorf("expected high/critical risk, got %q", result.RiskLevel)
	}
	if result.Boost <= 1.0 {
		t.Errorf("expected boost > 1.0 from combos, got %f", result.Boost)
	}
	if len(result.Explanations) == 0 {
		t.Error("expected explanations, got none")
	}
}

func TestEndToEnd_LowRisk(t *testing.T) {
	se := NewScoringEngine()

	findings := []Finding{
		finding("mod", 0.2, 0.5, StrengthMinimal),
	}

	result := se.CalculateScore(findings)

	if result.FinalConfidence > 0.3 {
		t.Errorf("expected low confidence, got %f", result.FinalConfidence)
	}
	if result.RiskLevel == RiskHigh || result.RiskLevel == RiskCritical {
		t.Errorf("expected low risk level, got %q", result.RiskLevel)
	}
}
