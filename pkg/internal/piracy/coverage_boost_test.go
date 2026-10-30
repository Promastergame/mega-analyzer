// Package piracy — coverage_boost_test.go
// Дополнительные тесты для повышения покрытия piracy-пакета
package piracy

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL MAPPING — покрываем все ветки mapFindingTypeToSignal
// ═══════════════════════════════════════════════════════════════════════════════

func TestMapFindingTypeToSignal_AllBranches(t *testing.T) {
	tests := []struct {
		input string
		want  SignalType
	}{
		{"site", SignalSource},
		{"path", SignalSource},
		{"mod", SignalBehavior},
		{"path_mod", SignalBehavior},
		{"crack", SignalCrack},
		{"watermark", SignalWatermark},
		{"encrypted", SignalObfuscation},
		{"obfuscated", SignalObfuscation},
		{"framework", SignalFramework},
		{"crack_tool", SignalCrackTool},
		{"malware", SignalMalware},
		{"unknown_xyz", SignalBehavior},
		{"", SignalBehavior},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapFindingTypeToSignal(tt.input)
			if got != tt.want {
				t.Errorf("mapFindingTypeToSignal(%q) = %q, want %q",
					tt.input, got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INFER STRENGTH — все ветки вывода силы
// ═══════════════════════════════════════════════════════════════════════════════

func TestInferStrength_AllBranches(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name string
		f    Finding
		want SignalStrength
	}{
		// Explicit strength — каждый уровень
		{"explicit critical", Finding{Strength: StrengthCritical, Type: "mod"}, StrengthCritical},
		{"explicit strong", Finding{Strength: StrengthStrong, Type: "mod"}, StrengthStrong},
		{"explicit medium", Finding{Strength: StrengthMedium, Type: "mod"}, StrengthMedium},
		{"explicit weak", Finding{Strength: StrengthWeak, Type: "mod"}, StrengthWeak},
		{"explicit minimal", Finding{Strength: StrengthMinimal, Type: "mod"}, StrengthMinimal},

		// Risk tags
		{"tag malware", Finding{Type: "mod", RiskTags: []string{"malware"}}, StrengthCritical},
		{"tag crack", Finding{Type: "mod", RiskTags: []string{"crack"}}, StrengthStrong},
		{"tag bypass", Finding{Type: "mod", RiskTags: []string{"bypass"}}, StrengthStrong},
		{"tag irrelevant", Finding{Type: "mod", RiskTags: []string{"info"}}, StrengthWeak},

		// By signal type fallback
		{"type malware", Finding{Type: "malware"}, StrengthCritical},
		{"type crack_tool", Finding{Type: "crack_tool"}, StrengthCritical},
		{"type crack", Finding{Type: "crack"}, StrengthStrong},
		{"type framework", Finding{Type: "framework"}, StrengthMedium},
		{"type site", Finding{Type: "site"}, StrengthMedium},
		{"type watermark", Finding{Type: "watermark"}, StrengthMedium},
		{"type encrypted", Finding{Type: "encrypted"}, StrengthWeak},
		{"type obfuscated", Finding{Type: "obfuscated"}, StrengthWeak},
		{"type mod", Finding{Type: "mod"}, StrengthWeak},
		{"type path", Finding{Type: "path"}, StrengthMedium},
		{"type unknown", Finding{Type: "banana"}, StrengthWeak},
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
// RISK LEVEL — граничные значения
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetRiskLevel_Boundaries(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		conf float64
		want RiskLevel
	}{
		{0.00, RiskMinimal},
		{0.01, RiskMinimal},
		{0.29, RiskMinimal},
		{0.30, RiskLow},
		{0.49, RiskLow},
		{0.50, RiskMedium},
		{0.69, RiskMedium},
		{0.70, RiskHigh},
		{0.89, RiskHigh},
		{0.90, RiskCritical},
		{0.99, RiskCritical},
		{1.00, RiskCritical},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := se.getRiskLevel(tt.conf)
			if got != tt.want {
				t.Errorf("getRiskLevel(%f) = %q, want %q", tt.conf, got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINATION BOOST — все комбинации по отдельности
// ═══════════════════════════════════════════════════════════════════════════════

func TestCombinationBoost_EachCombo(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name     string
		findings []Finding
		wantMin  float64
		wantMax  float64
	}{
		{
			name: "source+watermark",
			findings: []Finding{
				finding("site", 0.7, 1.0, StrengthMedium),
				finding("watermark", 0.7, 1.0, StrengthMedium),
			},
			wantMin: 1.19,
			wantMax: 1.21,
		},
		{
			name: "watermark+crack",
			findings: []Finding{
				finding("watermark", 0.8, 1.0, StrengthMedium),
				finding("crack", 0.8, 1.0, StrengthStrong),
			},
			wantMin: 1.29,
			wantMax: 1.31,
		},
		{
			name: "crack_tool+behavior",
			findings: []Finding{
				finding("crack_tool", 0.9, 1.0, StrengthCritical),
				finding("mod", 0.5, 1.0, StrengthWeak),
			},
			wantMin: 1.24,
			wantMax: 1.26,
		},
		{
			name: "malware alone — no wildcard match",
			findings: []Finding{
				finding("malware", 0.9, 1.0, StrengthCritical),
			},
			wantMin: 1.0,
			wantMax: 1.01,
		},
		{
			name: "malware+other type triggers wildcard",
			findings: []Finding{
				finding("malware", 0.9, 1.0, StrengthCritical),
				finding("mod", 0.3, 1.0, StrengthWeak),
			},
			wantMin: 1.49,
			wantMax: 1.51,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := se.findingsToEvidence(tt.findings)
			groups := groupBySignal(evidence)
			boost := se.calculateCombinationBoost(groups)

			if boost < tt.wantMin || boost > tt.wantMax {
				t.Errorf("boost = %f, want [%f, %f]", boost, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BOOST CAPPING — не превышает maxBoost
// ═══════════════════════════════════════════════════════════════════════════════

func TestCombinationBoost_CappedAtMax(t *testing.T) {
	se := NewScoringEngine()

	// Все комбинации одновременно: watermark+crack+source+malware+crack_tool+behavior
	findings := []Finding{
		finding("watermark", 0.9, 1.0, StrengthMedium),
		finding("crack", 0.9, 1.0, StrengthStrong),
		finding("site", 0.9, 1.0, StrengthMedium),
		finding("malware", 0.95, 1.0, StrengthCritical),
		finding("crack_tool", 0.9, 1.0, StrengthCritical),
		finding("mod", 0.8, 1.0, StrengthWeak),
	}

	evidence := se.findingsToEvidence(findings)
	groups := groupBySignal(evidence)
	boost := se.calculateCombinationBoost(groups)

	if boost > se.cfg.MaxBoost {
		t.Errorf("boost %f exceeds maxBoost %f", boost, se.cfg.MaxBoost)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE CAPPING — финальная уверенность ≤ 1.0
// ═══════════════════════════════════════════════════════════════════════════════

func TestFinalConfidence_NeverExceedsOne(t *testing.T) {
	se := NewScoringEngine()

	// Максимально "горячий" набор
	findings := []Finding{
		finding("malware", 1.0, 1.0, StrengthCritical),
		finding("crack_tool", 1.0, 1.0, StrengthCritical),
		finding("crack", 1.0, 1.0, StrengthCritical),
		finding("watermark", 1.0, 1.0, StrengthCritical),
		finding("site", 1.0, 1.0, StrengthCritical),
		finding("mod", 1.0, 1.0, StrengthCritical),
		finding("framework", 1.0, 1.0, StrengthCritical),
		finding("encrypted", 1.0, 1.0, StrengthCritical),
	}

	result := se.CalculateScore(findings)
	if result.FinalConfidence > 1.0 {
		t.Errorf("FinalConfidence = %f, must be ≤ 1.0", result.FinalConfidence)
	}
	if result.RiskLevel != RiskCritical {
		t.Errorf("expected critical risk, got %q", result.RiskLevel)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLANATIONS — проверяем что генерируются
// ═══════════════════════════════════════════════════════════════════════════════

func TestExplanations_NonEmpty(t *testing.T) {
	se := NewScoringEngine()

	tests := []struct {
		name     string
		findings []Finding
	}{
		{
			name: "single finding",
			findings: []Finding{
				finding("mod", 0.5, 1.0, StrengthWeak),
			},
		},
		{
			name: "combo with boost",
			findings: []Finding{
				finding("watermark", 0.8, 1.0, StrengthMedium),
				finding("crack", 0.8, 1.0, StrengthStrong),
			},
		},
		{
			name: "malware warning",
			findings: []Finding{
				finding("malware", 0.9, 1.0, StrengthCritical),
				finding("mod", 0.3, 1.0, StrengthWeak),
			},
		},
		{
			name: "crack_tool warning",
			findings: []Finding{
				finding("crack_tool", 0.8, 1.0, StrengthCritical),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := se.CalculateScore(tt.findings)
			if len(result.Explanations) == 0 {
				t.Error("expected explanations, got none")
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL BREAKDOWN — все типы присутствуют в breakdown
// ═══════════════════════════════════════════════════════════════════════════════

func TestSignalBreakdown_ContainsAllTypes(t *testing.T) {
	se := NewScoringEngine()

	findings := []Finding{
		finding("malware", 0.9, 1.0, StrengthCritical),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("watermark", 0.7, 1.0, StrengthMedium),
		finding("mod", 0.5, 1.0, StrengthWeak),
	}

	result := se.CalculateScore(findings)

	expectedTypes := []SignalType{SignalMalware, SignalCrack, SignalWatermark, SignalBehavior}
	for _, st := range expectedTypes {
		if _, ok := result.SignalBreakdown[st]; !ok {
			t.Errorf("breakdown missing signal type %q", st)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOP EVIDENCE — правильная сортировка
// ═══════════════════════════════════════════════════════════════════════════════

func TestTopEvidence_SortedByScore(t *testing.T) {
	se := NewScoringEngine()

	findings := []Finding{
		finding("mod", 0.2, 0.5, StrengthMinimal),      // lowest
		finding("crack", 0.9, 1.0, StrengthStrong),     // highest
		finding("watermark", 0.6, 0.8, StrengthMedium), // middle
	}

	result := se.CalculateScore(findings)

	if len(result.TopEvidence) == 0 {
		t.Fatal("no top evidence")
	}

	// Первый элемент должен быть crack (самый сильный)
	if result.TopEvidence[0].Type != SignalCrack {
		t.Errorf("top evidence[0] = %q, want %q", result.TopEvidence[0].Type, SignalCrack)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE COUNT
// ═══════════════════════════════════════════════════════════════════════════════

func TestEvidenceCount_MatchesFindings(t *testing.T) {
	se := NewScoringEngine()

	findings := []Finding{
		finding("mod", 0.5, 1.0, StrengthWeak),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("site", 0.6, 0.8, StrengthMedium),
	}

	result := se.CalculateScore(findings)

	if result.EvidenceCount != len(findings) {
		t.Errorf("EvidenceCount = %d, want %d", result.EvidenceCount, len(findings))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM CONFIG — движок с нестандартными параметрами
// ═══════════════════════════════════════════════════════════════════════════════

func TestCustomConfig_HigherDecay(t *testing.T) {
	// Используем ОДИН тип сигнала, чтобы:
	// 1. Нет combo boost (boost = 1.0 для обоих)
	// 2. Decay влияет на 2-й и 3-й элемент группы
	// 3. typeAvg (BlendAvg) меняется из-за decay

	findings := []Finding{
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
		finding("crack", 0.8, 1.0, StrengthStrong),
	}

	// Default decay = 0.7
	defaultEngine := NewScoringEngine()
	defaultResult := defaultEngine.CalculateScore(findings)

	// Aggressive decay = 0.2
	cfg := DefaultScoringConfig()
	cfg.DuplicateDecay = 0.2
	aggressiveEngine, err := NewScoringEngineWithConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	aggressiveResult := aggressiveEngine.CalculateScore(findings)

	// No decay = 1.0
	cfg2 := DefaultScoringConfig()
	cfg2.DuplicateDecay = 1.0
	noDecayEngine, err := NewScoringEngineWithConfig(cfg2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	noDecayResult := noDecayEngine.CalculateScore(findings)

	t.Logf("no decay (1.0):    conf=%f base=%f boost=%f",
		noDecayResult.FinalConfidence, noDecayResult.BaseConfidence, noDecayResult.Boost)
	t.Logf("default  (0.7):    conf=%f base=%f boost=%f",
		defaultResult.FinalConfidence, defaultResult.BaseConfidence, defaultResult.Boost)
	t.Logf("aggressive(0.2):   conf=%f base=%f boost=%f",
		aggressiveResult.FinalConfidence, aggressiveResult.BaseConfidence, aggressiveResult.Boost)

	// Строгий порядок: no_decay >= default >= aggressive
	if aggressiveResult.BaseConfidence >= defaultResult.BaseConfidence {
		t.Errorf("aggressive decay base (%f) should be < default base (%f)",
			aggressiveResult.BaseConfidence, defaultResult.BaseConfidence)
	}
	if defaultResult.BaseConfidence >= noDecayResult.BaseConfidence {
		t.Errorf("default decay base (%f) should be < no-decay base (%f)",
			defaultResult.BaseConfidence, noDecayResult.BaseConfidence)
	}
}

func TestDuplicateDecay_MonotonicAcrossTypes(t *testing.T) {
	findings := []Finding{
		finding("crack", 0.7, 1.0, StrengthStrong),
		finding("crack", 0.7, 1.0, StrengthStrong),
		finding("crack", 0.7, 1.0, StrengthStrong),
		finding("watermark", 0.7, 1.0, StrengthMedium),
		finding("watermark", 0.7, 1.0, StrengthMedium),
		finding("watermark", 0.7, 1.0, StrengthMedium),
		finding("mod", 0.7, 1.0, StrengthWeak),
		finding("mod", 0.7, 1.0, StrengthWeak),
		finding("mod", 0.7, 1.0, StrengthWeak),
	}

	calcBase := func(decay float64) float64 {
		cfg := DefaultScoringConfig()
		cfg.DuplicateDecay = decay
		se, _ := NewScoringEngineWithConfig(cfg)

		evidence := se.findingsToEvidence(findings)
		groups := groupBySignal(evidence)

		return se.calculateBaseConfidence(evidence, groups)
	}

	baseLow := calcBase(0.3)
	baseMid := calcBase(0.7)
	baseHigh := calcBase(1.0)

	const eps = 1e-6
	if baseLow > baseMid+eps {
		t.Errorf("expected base(0.3) <= base(0.7), got %f > %f", baseLow, baseMid)
	}
	if baseMid > baseHigh+eps {
		t.Errorf("expected base(0.7) <= base(1.0), got %f > %f", baseMid, baseHigh)
	}
}

func TestNewScoringEngineWithConfig_InvalidReturnsError(t *testing.T) {
	cfg := DefaultScoringConfig()
	cfg.MaxBoost = 0.1 // невалидно

	_, err := NewScoringEngineWithConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENHANCE RESULT — интеграция с Result
// ═══════════════════════════════════════════════════════════════════════════════

func TestEnhanceResultWithScoring(t *testing.T) {
	se := NewScoringEngine()

	result := &Result{
		Findings: []Finding{
			finding("malware", 0.9, 1.0, StrengthCritical),
			finding("crack", 0.8, 1.0, StrengthStrong),
			finding("mod", 0.5, 1.0, StrengthWeak),
		},
	}

	se.EnhanceResultWithScoring(result)

	if result.Confidence == 0 {
		t.Error("expected non-zero confidence after enhancement")
	}
	if result.RiskLevel == "" {
		t.Error("expected non-empty risk level after enhancement")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINATION KEY — String() и валидация
// ═══════════════════════════════════════════════════════════════════════════════

func TestCombinationKey_String(t *testing.T) {
	tests := []struct {
		key  CombinationKey
		want string
	}{
		{ComboWatermarkCrack, "watermark+crack"},
		{ComboMalwareAny, "malware+any"},
		{ComboMultipleCritical, "multiple_critical"},
		{ComboCrackToolBehav, "crack_tool+behavior"},
		{ComboSourceWatermark, "source+watermark"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.key.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG SERIALIZATION — round-trip
// ═══════════════════════════════════════════════════════════════════════════════

func TestConfigSaveLoad_RoundTrip(t *testing.T) {
	cfg := DefaultScoringConfig()

	tmpFile := t.TempDir() + "/scoring_config.json"

	if err := cfg.SaveScoringConfig(tmpFile); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := LoadScoringConfig(tmpFile)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// Проверяем ключевые поля
	if loaded.MaxBoost != cfg.MaxBoost {
		t.Errorf("MaxBoost: got %f, want %f", loaded.MaxBoost, cfg.MaxBoost)
	}
	if loaded.DuplicateDecay != cfg.DuplicateDecay {
		t.Errorf("DuplicateDecay: got %f, want %f", loaded.DuplicateDecay, cfg.DuplicateDecay)
	}
	if len(loaded.CombinationBoosts) != len(cfg.CombinationBoosts) {
		t.Errorf("CombinationBoosts count: got %d, want %d",
			len(loaded.CombinationBoosts), len(cfg.CombinationBoosts))
	}
	for k, v := range cfg.CombinationBoosts {
		if loaded.CombinationBoosts[k] != v {
			t.Errorf("boost %s: got %f, want %f", k, loaded.CombinationBoosts[k], v)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// METRICS — потокобезопасность и корректность
// ═══════════════════════════════════════════════════════════════════════════════

func TestScoringMetrics_Record(t *testing.T) {
	m := NewScoringMetrics()

	m.Record(&ScoringResult{
		FinalConfidence: 0.95,
		Boost:           1.3,
		RiskLevel:       RiskCritical,
	}, 100_000) // 100μs

	m.Record(&ScoringResult{
		FinalConfidence: 0.4,
		Boost:           1.0,
		RiskLevel:       RiskLow,
	}, 50_000)

	snap := m.Snapshot()

	if snap["total_scored"].(int64) != 2 {
		t.Errorf("total_scored = %v, want 2", snap["total_scored"])
	}
	if snap["total_critical"].(int64) != 1 {
		t.Errorf("total_critical = %v, want 1", snap["total_critical"])
	}
	if snap["total_boosted"].(int64) != 1 {
		t.Errorf("total_boosted = %v, want 1", snap["total_boosted"])
	}
	if snap["max_confidence"].(float64) != 0.95 {
		t.Errorf("max_confidence = %v, want 0.95", snap["max_confidence"])
	}
}

func TestInstrumentedEngine_TracksMetrics(t *testing.T) {
	engine := NewInstrumentedScoringEngine()

	for i := 0; i < 10; i++ {
		engine.CalculateScore([]Finding{
			finding("mod", 0.5, 1.0, StrengthWeak),
		})
	}

	snap := engine.Metrics.Snapshot()
	if snap["total_scored"].(int64) != 10 {
		t.Errorf("expected 10 scored, got %v", snap["total_scored"])
	}
}
