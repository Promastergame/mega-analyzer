// Package piracy — scoring_config.go
// Externalizable, validatable scoring configuration
package piracy

import (
	"encoding/json"
	"fmt"
	"os"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RISK THRESHOLD — порог для определения уровня риска
// ═══════════════════════════════════════════════════════════════════════════════

type RiskThreshold struct {
	MinConfidence float64   `json:"min_confidence"`
	Level         RiskLevel `json:"level"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING CONFIG — вся конфигурация в одной структуре
// ═══════════════════════════════════════════════════════════════════════════════

type ScoringConfig struct {
	// Веса по силе сигнала (0.0 – 1.0)
	SignalWeights map[SignalStrength]float64 `json:"signal_weights"`

	// Множители при обнаружении комбинации сигналов
	CombinationBoosts map[CombinationKey]float64 `json:"-"`

	// Для JSON: сериализуемое представление бустов
	CombinationBoostsRaw []comboBoostEntry `json:"combination_boosts"`

	// Минимальное количество critical-сигналов для срабатывания MultipleCritical
	MultipleCriticalThreshold int `json:"multiple_critical_threshold"`

	// Предельный суммарный буст
	MaxBoost float64 `json:"max_boost"`

	// Пороги уровней риска (отсортированы по убыванию MinConfidence)
	RiskThresholds []RiskThreshold `json:"risk_thresholds"`

	// Коэффициент затухания для повторных сигналов одного типа.
	// Каждый следующий Evidence того же SignalType умножается на decay^(index).
	// 1.0 = нет затухания, 0.5 = каждый следующий в два раза слабее.
	DuplicateDecay float64 `json:"duplicate_decay"`

	// Блендинг base confidence: доли max, avg, diversity
	BlendMax       float64 `json:"blend_max"`
	BlendAvg       float64 `json:"blend_avg"`
	BlendDiversity float64 `json:"blend_diversity"`
	// Делитель для diversity (len(evidence)/DiversityCap)
	DiversityCap float64 `json:"diversity_cap"`
}

// comboBoostEntry — JSON-представление одного буста
type comboBoostEntry struct {
	First  SignalType `json:"first"`
	Second SignalType `json:"second,omitempty"` // "" = any
	Boost  float64    `json:"boost"`
	// Для special sentinel ComboMultipleCritical
	Special string `json:"special,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

func DefaultScoringConfig() ScoringConfig {
	cfg := ScoringConfig{
		SignalWeights: map[SignalStrength]float64{
			StrengthCritical: 1.0,
			StrengthStrong:   0.85,
			StrengthMedium:   0.65,
			StrengthWeak:     0.4,
			StrengthMinimal:  0.15,
		},
		CombinationBoosts: map[CombinationKey]float64{
			ComboWatermarkCrack:   1.30,
			ComboCrackToolBehav:   1.25,
			ComboSourceWatermark:  1.20,
			ComboMalwareAny:       1.50,
			ComboMultipleCritical: 1.40,
		},
		MultipleCriticalThreshold: 2,
		MaxBoost:                  2.0,
		RiskThresholds: []RiskThreshold{
			{0.9, RiskCritical},
			{0.7, RiskHigh},
			{0.5, RiskMedium},
			{0.3, RiskLow},
			{0.0, RiskMinimal},
		},
		DuplicateDecay: 0.7,
		BlendMax:       0.60,
		BlendAvg:       0.30,
		BlendDiversity: 0.10,
		DiversityCap:   10.0,
	}
	cfg.syncBoostsRaw()
	return cfg
}

func (c *ScoringConfig) syncBoostsRaw() {
	c.CombinationBoostsRaw = make([]comboBoostEntry, 0, len(c.CombinationBoosts))
	for k, v := range c.CombinationBoosts {
		entry := comboBoostEntry{First: k.First, Second: k.Second, Boost: v}
		if k == ComboMultipleCritical {
			entry.Special = "multiple_critical"
		}
		c.CombinationBoostsRaw = append(c.CombinationBoostsRaw, entry)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

func (c *ScoringConfig) Validate() error {
	// Проверяем, что все силы сигналов имеют вес
	for _, s := range AllStrengths {
		w, ok := c.SignalWeights[s]
		if !ok {
			return fmt.Errorf("missing weight for strength %q", s)
		}
		if w < 0 || w > 1 {
			return fmt.Errorf("weight for %q out of [0,1]: %f", s, w)
		}
	}

	// Бусты должны быть >= 1.0
	for k, v := range c.CombinationBoosts {
		if v < 1.0 {
			return fmt.Errorf("combination boost %s < 1.0: %f", k, v)
		}
	}

	if c.MaxBoost < 1.0 {
		return fmt.Errorf("max_boost must be >= 1.0, got %f", c.MaxBoost)
	}

	if c.MultipleCriticalThreshold < 1 {
		return fmt.Errorf("multiple_critical_threshold must be >= 1")
	}

	if len(c.RiskThresholds) == 0 {
		return fmt.Errorf("risk_thresholds must not be empty")
	}

	if c.DuplicateDecay <= 0 || c.DuplicateDecay > 1 {
		return fmt.Errorf("duplicate_decay must be in (0, 1], got %f", c.DuplicateDecay)
	}

	// Blend weights должны суммироваться приблизительно в 1.0
	sum := c.BlendMax + c.BlendAvg + c.BlendDiversity
	if sum < 0.99 || sum > 1.01 {
		return fmt.Errorf("blend weights must sum to 1.0, got %f", sum)
	}

	if c.DiversityCap <= 0 {
		return fmt.Errorf("diversity_cap must be > 0")
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON SERIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

func LoadScoringConfig(path string) (ScoringConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ScoringConfig{}, fmt.Errorf("read config: %w", err)
	}

	var cfg ScoringConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ScoringConfig{}, fmt.Errorf("parse config: %w", err)
	}

	// Reconstruct typed map from raw entries
	cfg.CombinationBoosts = make(map[CombinationKey]float64, len(cfg.CombinationBoostsRaw))
	for _, entry := range cfg.CombinationBoostsRaw {
		var key CombinationKey
		if entry.Special == "multiple_critical" {
			key = ComboMultipleCritical
		} else {
			key = CombinationKey{First: entry.First, Second: entry.Second}
		}
		cfg.CombinationBoosts[key] = entry.Boost
	}

	if err := cfg.Validate(); err != nil {
		return ScoringConfig{}, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *ScoringConfig) SaveScoringConfig(path string) error {
	c.syncBoostsRaw()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
