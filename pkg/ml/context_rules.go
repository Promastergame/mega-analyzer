package ml

import (
	"encoding/json"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL RULES — правила скоринга сигналов с очками
// ═══════════════════════════════════════════════════════════════════════════════

// SignalRule — правило для сигнала с контекстными модификаторами
type SignalRule struct {
	Signal      string          `json:"signal"`
	Description string          `json:"description,omitempty"`
	BasePoints  int             `json:"base_points"`
	ContextMods map[AppType]int `json:"context_mods,omitempty"`
	Category    SignalCategory  `json:"category,omitempty"`
	Severity    string          `json:"severity,omitempty"` // info, low, medium, high, critical
}

// SignalCategory — категория сигнала
type SignalCategory string

const (
	CategoryPermission   SignalCategory = "permission"
	CategoryNetwork      SignalCategory = "network"
	CategoryCode         SignalCategory = "code"
	CategoryBehavior     SignalCategory = "behavior"
	CategoryObfuscation  SignalCategory = "obfuscation"
	CategoryPersistence  SignalCategory = "persistence"
	CategoryExfiltration SignalCategory = "exfiltration"
)

// GetPoints возвращает очки для сигнала с учётом контекста
func (sr *SignalRule) GetPoints(appType AppType) (base, mod, total int) {
	base = sr.BasePoints

	if sr.ContextMods != nil {
		if m, ok := sr.ContextMods[appType]; ok {
			mod = m
		}
	}

	total = base + mod
	if total < 0 {
		total = 0 // не может быть отрицательным
	}

	return base, mod, total
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBO RULES — правила для опасных комбинаций
// ═══════════════════════════════════════════════════════════════════════════════

// ComboRule — правило для комбинации сигналов
type ComboRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Signals     []string `json:"signals"`          // все должны присутствовать
	AnyOf       []string `json:"any_of,omitempty"` // хотя бы один (опционально)
	BonusPoints int      `json:"bonus_points"`
	ThreatName  string   `json:"threat_name,omitempty"`
	ThreatType  string   `json:"threat_type,omitempty"` // trojan, spyware, banker, etc.
	Severity    string   `json:"severity"`              // critical, high, medium, low
	MITRE       string   `json:"mitre,omitempty"`       // MITRE ATT&CK reference
}

// Matches проверяет, совпадает ли комбо с набором сигналов
func (cr *ComboRule) Matches(signals []string) bool {
	signalSet := make(map[string]struct{}, len(signals))
	for _, s := range signals {
		signalSet[s] = struct{}{}
	}

	// Все обязательные сигналы должны присутствовать
	for _, required := range cr.Signals {
		if _, ok := signalSet[required]; !ok {
			return false
		}
	}

	// Если есть AnyOf, хотя бы один должен присутствовать
	if len(cr.AnyOf) > 0 {
		found := false
		for _, optional := range cr.AnyOf {
			if _, ok := signalSet[optional]; ok {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT LEVEL — уровень угрозы (переименовано из RiskLevel чтобы не конфликтовать)
// ═══════════════════════════════════════════════════════════════════════════════

// ThreatLevel — уровень угрозы для контекстного скоринга
type ThreatLevel string

const (
	ThreatNone     ThreatLevel = "none"
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

// ThreatLevelInfo — информация об уровне угрозы
type ThreatLevelInfo struct {
	Level       ThreatLevel
	DisplayName string
	Color       string // для UI
	Icon        string
	MinScore    int
	MaxScore    int
}

var threatLevelInfos = map[ThreatLevel]ThreatLevelInfo{
	ThreatNone: {
		Level:       ThreatNone,
		DisplayName: "None",
		Color:       "gray",
		Icon:        "✓",
		MinScore:    0,
		MaxScore:    0,
	},
	ThreatLow: {
		Level:       ThreatLow,
		DisplayName: "Low",
		Color:       "green",
		Icon:        "◐",
		MinScore:    1,
		MaxScore:    15,
	},
	ThreatMedium: {
		Level:       ThreatMedium,
		DisplayName: "Medium",
		Color:       "yellow",
		Icon:        "◑",
		MinScore:    16,
		MaxScore:    40,
	},
	ThreatHigh: {
		Level:       ThreatHigh,
		DisplayName: "High",
		Color:       "orange",
		Icon:        "●",
		MinScore:    41,
		MaxScore:    70,
	},
	ThreatCritical: {
		Level:       ThreatCritical,
		DisplayName: "Critical",
		Color:       "red",
		Icon:        "⬤",
		MinScore:    71,
		MaxScore:    999,
	},
}

// GetThreatLevelInfo возвращает информацию об уровне угрозы
func GetThreatLevelInfo(level ThreatLevel) ThreatLevelInfo {
	if info, ok := threatLevelInfos[level]; ok {
		return info
	}
	return threatLevelInfos[ThreatNone]
}

// ThreatThresholds — пороги для определения уровня угрозы
type ThreatThresholds struct {
	Low      int `json:"low"`      // 1-15
	Medium   int `json:"medium"`   // 16-40
	High     int `json:"high"`     // 41-70
	Critical int `json:"critical"` // 71+
}

// DefaultThreatThresholds — дефолтные пороги
var DefaultThreatThresholds = ThreatThresholds{
	Low:      15,
	Medium:   40,
	High:     70,
	Critical: 71,
}

// GetLevel определяет уровень угрозы по очкам
func (tt ThreatThresholds) GetLevel(score int) ThreatLevel {
	switch {
	case score <= 0:
		return ThreatNone
	case score <= tt.Low:
		return ThreatLow
	case score <= tt.Medium:
		return ThreatMedium
	case score <= tt.High:
		return ThreatHigh
	default:
		return ThreatCritical
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT RULES — полный набор правил
// ═══════════════════════════════════════════════════════════════════════════════

// ContextRules — полный набор правил контекстного скоринга
type ContextRules struct {
	Version     string                 `json:"version"`
	SignalRules map[string]*SignalRule `json:"signal_rules"`
	ComboRules  []ComboRule            `json:"combo_rules"`
	Thresholds  ThreatThresholds       `json:"thresholds"`
}

// NewContextRules создаёт правила по умолчанию
func NewContextRules() *ContextRules {
	return &ContextRules{
		Version:     "1.0",
		SignalRules: defaultSignalRules(),
		ComboRules:  defaultComboRules(),
		Thresholds:  DefaultThreatThresholds,
	}
}

// LoadContextRules загружает правила из JSON
func LoadContextRules(data []byte) (*ContextRules, error) {
	rules := NewContextRules()
	if err := json.Unmarshal(data, rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// GetSignalRule возвращает правило для сигнала
func (cr *ContextRules) GetSignalRule(signal string) *SignalRule {
	if rule, ok := cr.SignalRules[signal]; ok {
		return rule
	}
	// Возвращаем дефолтное правило для неизвестных сигналов
	return &SignalRule{
		Signal:     signal,
		BasePoints: 1,
	}
}

// FindMatchingCombos находит все совпадающие комбо
func (cr *ContextRules) FindMatchingCombos(signals []string) []ComboRule {
	var matches []ComboRule
	for _, combo := range cr.ComboRules {
		if combo.Matches(signals) {
			matches = append(matches, combo)
		}
	}
	return matches
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT SIGNAL RULES — встроенные правила сигналов
// ═══════════════════════════════════════════════════════════════════════════════

func defaultSignalRules() map[string]*SignalRule {
	return map[string]*SignalRule{
		// ═══════════════════════════════════════════════════════════════════
		// PERMISSION-BASED SIGNALS
		// ═══════════════════════════════════════════════════════════════════

		"overlay_permission": {
			Signal:      "overlay_permission",
			Description: "SYSTEM_ALERT_WINDOW permission for overlay",
			BasePoints:  4, // Уменьшено с 5: часто легитимно для UI
			Category:    CategoryPermission,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeBanking:       +12,
				AppTypePayment:       +10,
				AppTypeCrypto:        +10,
				AppTypeAccessibility: -3,
				AppTypeLauncher:      -4,
				AppTypeGaming:        +2,
				AppTypeMalware:       +15,
				AppTypeGeneric:       +3,
			},
		},

		"accessibility_service": {
			Signal:      "accessibility_service",
			Description: "BIND_ACCESSIBILITY_SERVICE permission",
			BasePoints:  3, // Уменьшено с 8: часто library code из androidx
			Category:    CategoryPermission,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeAccessibility: -10,
				AppTypeSecurity:      -5,
				AppTypeLauncher:      -4,
				AppTypeBanking:       +12,
				AppTypePayment:       +10,
				AppTypeCrypto:        +10,
				AppTypeMalware:       +18,
				AppTypeGeneric:       +3,
			},
		},

		"device_admin": {
			Signal:      "device_admin",
			Description: "BIND_DEVICE_ADMIN permission",
			BasePoints:  10,
			Category:    CategoryPermission,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeSecurity: -8,
				AppTypeSystem:   -5,
				AppTypeBanking:  +18,
				AppTypePayment:  +15,
				AppTypeMalware:  +25,
				AppTypeGeneric:  +8,
			},
		},

		"notification_listener": {
			Signal:      "notification_listener",
			Description: "BIND_NOTIFICATION_LISTENER_SERVICE",
			BasePoints:  6,
			Category:    CategoryPermission,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeSecurity: -3,
				AppTypeLauncher: -2,
				AppTypeSocial:   -1,
				AppTypeBanking:  +10,
				AppTypePayment:  +8,
				AppTypeMalware:  +12,
				AppTypeGeneric:  +3,
			},
		},

		"sms_permission": {
			Signal:      "sms_permission",
			Description: "SMS send/receive permissions",
			BasePoints:  7,
			Category:    CategoryPermission,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeSocial:  -4,
				AppTypeBanking: +8,
				AppTypePayment: +8,
				AppTypeMalware: +15,
				AppTypeGeneric: +4,
			},
		},

		"install_packages": {
			Signal:      "install_packages",
			Description: "REQUEST_INSTALL_PACKAGES permission",
			BasePoints:  8,
			Category:    CategoryPermission,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeSecurity: -5,
				AppTypePiracy:   +2,
				AppTypeMalware:  +15,
				AppTypeGeneric:  +6,
			},
		},

		"usage_stats": {
			Signal:      "usage_stats",
			Description: "PACKAGE_USAGE_STATS permission",
			BasePoints:  5,
			Category:    CategoryPermission,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeSecurity: -4,
				AppTypeLauncher: -3,
				AppTypeMalware:  +10,
				AppTypeGeneric:  +3,
			},
		},

		"boot_receiver": {
			Signal:      "boot_receiver",
			Description: "RECEIVE_BOOT_COMPLETED for persistence",
			BasePoints:  3,
			Category:    CategoryPersistence,
			Severity:    "low",
			ContextMods: map[AppType]int{
				AppTypeSecurity: -2,
				AppTypeSocial:   -1,
				AppTypeMalware:  +8,
				AppTypeGeneric:  +1,
			},
		},

		"av_recording": {
			Signal:      "av_recording",
			Description: "Camera + Microphone together",
			BasePoints:  4,
			Category:    CategoryPermission,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeSocial:  -3,
				AppTypeGaming:  -2,
				AppTypeBanking: +8,
				AppTypeMalware: +10,
				AppTypeGeneric: +2,
			},
		},

		"background_location": {
			Signal:      "background_location",
			Description: "ACCESS_BACKGROUND_LOCATION",
			BasePoints:  5,
			Category:    CategoryPermission,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeSecurity: -2,
				AppTypeSocial:   +1,
				AppTypeMalware:  +8,
				AppTypeGeneric:  +2,
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// NETWORK SIGNALS
		// ═══════════════════════════════════════════════════════════════════

		"https_downgrade": {
			Signal:      "https_downgrade",
			Description: "HTTP used instead of HTTPS",
			BasePoints:  6,
			Category:    CategoryNetwork,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeBanking: +25,
				AppTypePayment: +20,
				AppTypeCrypto:  +20,
				AppTypePiracy:  -2,
				AppTypeGeneric: +4,
			},
		},

		"suspicious_url": {
			Signal:      "suspicious_url",
			Description: "Connection to suspicious domain",
			BasePoints:  8,
			Category:    CategoryNetwork,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeMalware: +12,
				AppTypeGeneric: +5,
			},
		},

		"piracy_url": {
			Signal:      "piracy_url",
			Description: "Connection to piracy-related domain",
			BasePoints:  12,
			Category:    CategoryNetwork,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypePiracy:  -10,
				AppTypeGeneric: +3,
			},
		},

		"hardcoded_network_address": {
			Signal:      "hardcoded_network_address",
			Description: "Hardcoded IP addresses or network endpoints in code",
			BasePoints:  8, // Увеличено: hardcoded IPs = высокий риск
			Category:    CategoryNetwork,
			Severity:    "critical",
			ContextMods: map[AppType]int{
				AppTypeBanking: +5,
				AppTypePayment: +5,
				AppTypeCrypto:  +5,
				AppTypeMalware: +10,
				AppTypeGeneric: +3,
			},
		},

		"c2_communication": {
			Signal:      "c2_communication",
			Description: "Potential C2 server communication",
			BasePoints:  20,
			Category:    CategoryNetwork,
			Severity:    "critical",
			ContextMods: map[AppType]int{
				AppTypeMalware: +15,
				AppTypeGeneric: +10,
			},
		},

		"data_exfiltration": {
			Signal:      "data_exfiltration",
			Description: "Potential data exfiltration pattern",
			BasePoints:  15,
			Category:    CategoryExfiltration,
			Severity:    "critical",
			ContextMods: map[AppType]int{
				AppTypeBanking: +20,
				AppTypeMalware: +15,
				AppTypeGeneric: +8,
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// CODE SIGNALS
		// ═══════════════════════════════════════════════════════════════════

		"dynamic_code_loading": {
			Signal:      "dynamic_code_loading",
			Description: "DexClassLoader or dynamic code loading",
			BasePoints:  7, // Увеличено с 10 до 7.5 (округлено): runtime code loading = опасно
			Category:    CategoryCode,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeGaming:   -3,
				AppTypeSecurity: -2,
				AppTypeMalware:  +15,
				AppTypeGeneric:  +5,
			},
		},

		"reflection_abuse": {
			Signal:      "reflection_abuse",
			Description: "Heavy use of reflection APIs",
			BasePoints:  2, // Уменьшено с 6: стандартная Java reflection в библиотеках
			Category:    CategoryCode,
			Severity:    "low",
			ContextMods: map[AppType]int{
				AppTypeMalware: +8,
				AppTypeGeneric: +2,
			},
		},

		"native_code": {
			Signal:      "native_code",
			Description: "Native code execution (JNI)",
			BasePoints:  3,
			Category:    CategoryCode,
			Severity:    "low",
			ContextMods: map[AppType]int{
				AppTypeGaming:   -2,
				AppTypeSecurity: -1,
				AppTypeMalware:  +5,
				AppTypeGeneric:  +1,
			},
		},

		"crypto_operations": {
			Signal:      "crypto_operations",
			Description: "Cryptographic operations detected",
			BasePoints:  2,
			Category:    CategoryCode,
			Severity:    "info",
			ContextMods: map[AppType]int{
				AppTypeBanking:  -1,
				AppTypeCrypto:   -2,
				AppTypeSecurity: -1,
				AppTypeMalware:  +5,
				AppTypeGeneric:  +1,
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// OBFUSCATION SIGNALS
		// ═══════════════════════════════════════════════════════════════════

		"heavy_obfuscation": {
			Signal:      "heavy_obfuscation",
			Description: "Heavy code obfuscation detected",
			BasePoints:  8,
			Category:    CategoryObfuscation,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeBanking:  -2,
				AppTypeSecurity: -3,
				AppTypeMalware:  +12,
				AppTypeGeneric:  +4,
			},
		},

		"string_encryption": {
			Signal:      "string_encryption",
			Description: "Encrypted strings in code",
			BasePoints:  5,
			Category:    CategoryObfuscation,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeBanking:  -1,
				AppTypeSecurity: -2,
				AppTypeMalware:  +8,
				AppTypeGeneric:  +3,
			},
		},

		"packer_detected": {
			Signal:      "packer_detected",
			Description: "Commercial or custom packer detected",
			BasePoints:  7,
			Category:    CategoryObfuscation,
			Severity:    "medium",
			ContextMods: map[AppType]int{
				AppTypeGaming:  -3,
				AppTypeMalware: +10,
				AppTypeGeneric: +4,
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// BEHAVIOR SIGNALS
		// ═══════════════════════════════════════════════════════════════════

		"keylogging": {
			Signal:      "keylogging",
			Description: "Potential keylogging behavior",
			BasePoints:  18,
			Category:    CategoryBehavior,
			Severity:    "critical",
			ContextMods: map[AppType]int{
				AppTypeAccessibility: -8,
				AppTypeBanking:       +20,
				AppTypeMalware:       +20,
				AppTypeGeneric:       +10,
			},
		},

		"screen_capture": {
			Signal:      "screen_capture",
			Description: "Screen capture/recording capability",
			BasePoints:  10,
			Category:    CategoryBehavior,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeSocial:  -3,
				AppTypeGaming:  -2,
				AppTypeBanking: +15,
				AppTypeMalware: +15,
				AppTypeGeneric: +5,
			},
		},

		"click_injection": {
			Signal:      "click_injection",
			Description: "Click/gesture injection detected",
			BasePoints:  12,
			Category:    CategoryBehavior,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeAccessibility: -6,
				AppTypeMalware:       +15,
				AppTypeGeneric:       +8,
			},
		},

		"anti_analysis": {
			Signal:      "anti_analysis",
			Description: "Anti-analysis/anti-debug techniques",
			BasePoints:  10,
			Category:    CategoryBehavior,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeBanking:  +2,
				AppTypeSecurity: -3,
				AppTypeMalware:  +15,
				AppTypeGeneric:  +6,
			},
		},

		"financial_target": {
			Signal:      "financial_target",
			Description: "Targeting financial applications",
			BasePoints:  15,
			Category:    CategoryBehavior,
			Severity:    "critical",
			ContextMods: map[AppType]int{
				AppTypeBanking:  +10,
				AppTypeSecurity: -5,
				AppTypeMalware:  +20,
				AppTypeGeneric:  +10,
			},
		},

		"hidden_activity": {
			Signal:      "hidden_activity",
			Description: "Hidden or transparent activity",
			BasePoints:  8,
			Category:    CategoryBehavior,
			Severity:    "high",
			ContextMods: map[AppType]int{
				AppTypeMalware: +12,
				AppTypeGeneric: +5,
			},
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT COMBO RULES — встроенные правила комбинаций
// ═══════════════════════════════════════════════════════════════════════════════

func defaultComboRules() []ComboRule {
	return []ComboRule{
		// CRITICAL
		{
			Name:        "trojan_overlay_admin",
			Description: "Overlay + Device Admin = classic banking trojan",
			Signals:     []string{"overlay_permission", "device_admin"},
			BonusPoints: 30,
			ThreatName:  "Trojan.OverlayAdmin",
			ThreatType:  "trojan",
			Severity:    "critical",
			MITRE:       "T1539",
		},
		{
			Name:        "banking_stealer",
			Description: "Accessibility + Overlay + Financial targeting",
			Signals:     []string{"accessibility_service", "overlay_permission", "financial_target"},
			BonusPoints: 40,
			ThreatName:  "BankBot.Stealer",
			ThreatType:  "banker",
			Severity:    "critical",
			MITRE:       "T1411",
		},
		{
			Name:        "accessibility_keylogger",
			Description: "Accessibility service with keylogging behavior",
			Signals:     []string{"accessibility_service", "keylogging"},
			BonusPoints: 35,
			ThreatName:  "Trojan.A11yKeylogger",
			ThreatType:  "spyware",
			Severity:    "critical",
			MITRE:       "T1056.001",
		},
		{
			Name:        "sms_stealer",
			Description: "SMS access + Internet + Boot persistence",
			Signals:     []string{"sms_permission", "boot_receiver"},
			AnyOf:       []string{"c2_communication", "data_exfiltration", "suspicious_url"},
			BonusPoints: 28,
			ThreatName:  "Trojan.SMSStealer",
			ThreatType:  "trojan",
			Severity:    "critical",
			MITRE:       "T1582",
		},
		{
			Name:        "otp_stealer",
			Description: "SMS + Notification listener (OTP interception)",
			Signals:     []string{"sms_permission", "notification_listener"},
			BonusPoints: 25,
			ThreatName:  "Trojan.OTPStealer",
			ThreatType:  "banker",
			Severity:    "critical",
		},

		// HIGH
		{
			Name:        "notification_spy",
			Description: "Notification listener + Overlay",
			Signals:     []string{"notification_listener", "overlay_permission"},
			BonusPoints: 22,
			ThreatName:  "Spyware.NotificationSpy",
			ThreatType:  "spyware",
			Severity:    "high",
			MITRE:       "T1417",
		},
		{
			Name:        "accessibility_overlay",
			Description: "Accessibility + Overlay without financial target",
			Signals:     []string{"accessibility_service", "overlay_permission"},
			BonusPoints: 18,
			ThreatName:  "Trojan.A11yOverlay",
			ThreatType:  "trojan",
			Severity:    "high",
		},
		{
			Name:        "click_fraud",
			Description: "Click injection + Hidden activity",
			Signals:     []string{"click_injection", "hidden_activity"},
			BonusPoints: 20,
			ThreatName:  "Trojan.ClickFraud",
			ThreatType:  "adware",
			Severity:    "high",
			MITRE:       "T1428",
		},
		{
			Name:        "screen_spy",
			Description: "Screen capture + Data exfiltration",
			Signals:     []string{"screen_capture", "data_exfiltration"},
			BonusPoints: 25,
			ThreatName:  "Spyware.ScreenCapture",
			ThreatType:  "spyware",
			Severity:    "high",
		},
		{
			Name:        "dropper",
			Description: "Install packages + Dynamic code loading",
			Signals:     []string{"install_packages", "dynamic_code_loading"},
			BonusPoints: 20,
			ThreatName:  "Trojan.Dropper",
			ThreatType:  "dropper",
			Severity:    "high",
			MITRE:       "T1544",
		},
		{
			Name:        "crypto_stealer",
			Description: "Clipboard + Crypto operations + Network",
			Signals:     []string{"crypto_operations"},
			AnyOf:       []string{"c2_communication", "data_exfiltration"},
			BonusPoints: 20,
			ThreatName:  "Trojan.CryptoStealer",
			ThreatType:  "stealer",
			Severity:    "high",
		},

		// MEDIUM
		{
			Name:        "persistence_network",
			Description: "Boot persistence + Suspicious network",
			Signals:     []string{"boot_receiver"},
			AnyOf:       []string{"c2_communication", "suspicious_url"},
			BonusPoints: 15,
			ThreatName:  "PUP.Persistent",
			ThreatType:  "pup",
			Severity:    "medium",
		},
		{
			Name:        "obfuscated_network",
			Description: "Heavy obfuscation + Network activity",
			Signals:     []string{"heavy_obfuscation"},
			AnyOf:       []string{"suspicious_url", "c2_communication", "data_exfiltration"},
			BonusPoints: 12,
			ThreatName:  "Suspicious.ObfuscatedNet",
			ThreatType:  "suspicious",
			Severity:    "medium",
		},
		{
			Name:        "anti_analysis_combo",
			Description: "Anti-analysis + Packer",
			Signals:     []string{"anti_analysis", "packer_detected"},
			BonusPoints: 10,
			ThreatName:  "Suspicious.Evasive",
			ThreatType:  "suspicious",
			Severity:    "medium",
		},
		{
			Name:        "location_exfil",
			Description: "Background location + Data exfiltration",
			Signals:     []string{"background_location", "data_exfiltration"},
			BonusPoints: 15,
			ThreatName:  "Spyware.LocationTracker",
			ThreatType:  "spyware",
			Severity:    "medium",
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// SortedSignalsByPoints возвращает сигналы отсортированные по очкам
func (cr *ContextRules) SortedSignalsByPoints(appType AppType) []string {
	type scoredSignal struct {
		signal string
		points int
	}

	scored := make([]scoredSignal, 0, len(cr.SignalRules))
	for name, rule := range cr.SignalRules {
		_, _, total := rule.GetPoints(appType)
		scored = append(scored, scoredSignal{name, total})
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].points > scored[j].points
	})

	result := make([]string, len(scored))
	for i, s := range scored {
		result[i] = s.signal
	}
	return result
}

// GetTopThreatsForAppType возвращает самые опасные сигналы для типа
func (cr *ContextRules) GetTopThreatsForAppType(appType AppType, n int) []string {
	sorted := cr.SortedSignalsByPoints(appType)
	if len(sorted) > n {
		return sorted[:n]
	}
	return sorted
}

// GetComboBySeverity возвращает комбо по severity
func (cr *ContextRules) GetComboBySeverity(severity string) []ComboRule {
	var result []ComboRule
	for _, combo := range cr.ComboRules {
		if combo.Severity == severity {
			result = append(result, combo)
		}
	}
	return result
}

// GetSignalsByCategory возвращает сигналы по категории
func (cr *ContextRules) GetSignalsByCategory(category SignalCategory) []*SignalRule {
	var result []*SignalRule
	for _, rule := range cr.SignalRules {
		if rule.Category == category {
			result = append(result, rule)
		}
	}
	return result
}
