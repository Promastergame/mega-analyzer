// Package piracy — signal.go
// Type-safe signal and strength definitions
package piracy

import "fmt"

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL TYPES — типобезопасные перечисления
// ═══════════════════════════════════════════════════════════════════════════════

type SignalType string

const (
	SignalSource      SignalType = "source"
	SignalBehavior    SignalType = "behavior"
	SignalCrack       SignalType = "crack"
	SignalWatermark   SignalType = "watermark"
	SignalFramework   SignalType = "framework"
	SignalObfuscation SignalType = "obfuscation"
	SignalMalware     SignalType = "malware"
	SignalCrackTool   SignalType = "crack_tool"
)

// AllSignalTypes — реестр всех допустимых типов сигналов.
// Используется для валидации конфига и итерации.
var AllSignalTypes = []SignalType{
	SignalSource, SignalBehavior, SignalCrack, SignalWatermark,
	SignalFramework, SignalObfuscation, SignalMalware, SignalCrackTool,
}

func (s SignalType) Valid() bool {
	for _, v := range AllSignalTypes {
		if s == v {
			return true
		}
	}
	return false
}

type SignalStrength string

const (
	StrengthCritical SignalStrength = "critical"
	StrengthStrong   SignalStrength = "strong"
	StrengthMedium   SignalStrength = "medium"
	StrengthWeak     SignalStrength = "weak"
	StrengthMinimal  SignalStrength = "minimal"
)

var AllStrengths = []SignalStrength{
	StrengthCritical, StrengthStrong, StrengthMedium, StrengthWeak, StrengthMinimal,
}

func (s SignalStrength) Valid() bool {
	for _, v := range AllStrengths {
		if s == v {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINATION KEY — типобезопасная замена строковых ключей бустов
// ═══════════════════════════════════════════════════════════════════════════════

// CombinationKey — пара сигналов, дающая буст при совместном обнаружении.
// Second == "" означает «этот сигнал + что угодно ещё».
type CombinationKey struct {
	First  SignalType
	Second SignalType // "" = wildcard ("any")
}

// Предопределённые комбинации — единственное место объявления ключей.
var (
	ComboWatermarkCrack   = CombinationKey{SignalWatermark, SignalCrack}
	ComboCrackToolBehav   = CombinationKey{SignalCrackTool, SignalBehavior}
	ComboSourceWatermark  = CombinationKey{SignalSource, SignalWatermark}
	ComboMalwareAny       = CombinationKey{First: SignalMalware} // wildcard
	ComboMultipleCritical = CombinationKey{}                     // special sentinel
)

func (k CombinationKey) String() string {
	if k == ComboMultipleCritical {
		return "multiple_critical"
	}
	second := string(k.Second)
	if second == "" {
		second = "any"
	}
	return fmt.Sprintf("%s+%s", k.First, second)
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK LEVEL
// ═══════════════════════════════════════════════════════════════════════════════

type RiskLevel string

const (
	RiskNone     RiskLevel = "none"
	RiskMinimal  RiskLevel = "minimal"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)
