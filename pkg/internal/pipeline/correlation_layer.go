package pipeline

import (
	"fmt"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL — единица данных от детектора
// ═══════════════════════════════════════════════════════════════════════════════

type Signal struct {
	ID       string         // уникальный ID сигнала (e.g. "overlay_perm_saw")
	Type     string         // "permission", "api_call", "pattern", "behavior"
	Value    string         // значение для матчинга (e.g. "SYSTEM_ALERT_WINDOW")
	Detector string         // какой детектор нашёл (e.g. "overlay_bank_detector")
	Score    int            // 1-100 (severity score)
	Severity types.Severity // severity enum из types
	Critical bool           // критически важный сигнал
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINATION THREAT — описание комбо-паттерна
// ═══════════════════════════════════════════════════════════════════════════════

type CombinationThreat struct {
	ID          string
	Name        string
	Description string
	Signals     []string // какие сигналы (Value или ID) должны присутствовать
	MinMatch    int      // минимум совпадений (0 = все обязательны)
	RiskLevel   string   // "low", "medium", "high", "critical"
	Risk        int      // 1-100+
	Mitigations []string

	// CheckFunc — опциональная кастомная проверка.
	// Если задана, Signals/MinMatch игнорируются, вызывается CheckFunc.
	// Используется для проверок, которые нельзя выразить через ID-матчинг
	// (например, "больше 15 permission-сигналов").
	CheckFunc func(signals []Signal) bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

type CorrelationEngine struct {
	mu sync.RWMutex

	signals      []Signal
	signalSet    map[string]struct{} // O(1) lookup по ID и Value
	threatMap    map[string]CombinationThreat
	foundThreats []CombinationThreat
}

func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		signals:      make([]Signal, 0, 64),
		signalSet:    make(map[string]struct{}, 128),
		threatMap:    getDefaultCombinationThreats(),
		foundThreats: make([]CombinationThreat, 0, 8),
	}
}

// ── Signal management ──────────────────────────────────────────────────────

// AddSignal добавляет один сигнал для корреляции
func (ce *CorrelationEngine) AddSignal(sig Signal) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.signals = append(ce.signals, sig)
}

// AddSignals добавляет пачку сигналов (batch — одна блокировка вместо N)
func (ce *CorrelationEngine) AddSignals(sigs []Signal) {
	if len(sigs) == 0 {
		return
	}
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.signals = append(ce.signals, sigs...)
}

// HasSignal проверяет наличие сигнала по ID или Value (O(1) после buildSignalSet)
func (ce *CorrelationEngine) HasSignal(idOrValue string) bool {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	_, ok := ce.signalSet[idOrValue]
	return ok
}

// GetSignalsByType возвращает все сигналы определённого типа
func (ce *CorrelationEngine) GetSignalsByType(typ string) []Signal {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var result []Signal
	for i := range ce.signals {
		if ce.signals[i].Type == typ {
			result = append(result, ce.signals[i])
		}
	}
	return result
}

// SignalCount возвращает количество накопленных сигналов
func (ce *CorrelationEngine) SignalCount() int {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return len(ce.signals)
}

// AddThreat добавляет кастомное правило (для расширения без изменения кода)
func (ce *CorrelationEngine) AddThreat(threat CombinationThreat) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.threatMap[threat.ID] = threat
}

// ── Signal set (internal) ──────────────────────────────────────────────────

// buildSignalSet создаёт set из всех ID и Value для O(1) проверок в checkThreat.
// Вызывается под write lock из AnalyzeCorrelations.
func (ce *CorrelationEngine) buildSignalSet() {
	// Clear без реаллокации (reuse underlying map)
	for k := range ce.signalSet {
		delete(ce.signalSet, k)
	}
	for i := range ce.signals {
		ce.signalSet[ce.signals[i].ID] = struct{}{}
		ce.signalSet[ce.signals[i].Value] = struct{}{}
	}
}

// ── Analysis ───────────────────────────────────────────────────────────────

// AnalyzeCorrelations выполняет анализ корреляций между всеми сигналами
func (ce *CorrelationEngine) AnalyzeCorrelations() []CombinationThreat {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	// Построить индекс сигналов для O(1) lookup
	ce.buildSignalSet()

	ce.foundThreats = ce.foundThreats[:0] // reuse slice

	for _, threat := range ce.threatMap {
		if ce.checkThreat(threat) {
			ce.foundThreats = append(ce.foundThreats, threat)
		}
	}

	return ce.foundThreats
}

// checkThreat проверяет, срабатывает ли одна угроза.
//
// Поддерживает три режима:
//  1. CheckFunc != nil      → кастомная проверка (полный доступ к сигналам)
//  2. MinMatch > 0          → "как минимум N из M" (partial matching)
//  3. MinMatch == 0         → все Signals обязательны (AND-логика, как раньше)
func (ce *CorrelationEngine) checkThreat(threat CombinationThreat) bool {
	// Режим 1: кастомная проверка
	if threat.CheckFunc != nil {
		return threat.CheckFunc(ce.signals)
	}

	if len(threat.Signals) == 0 {
		return false
	}

	// O(m) вместо O(n*m) благодаря signalSet
	matchedCount := 0
	for _, req := range threat.Signals {
		if _, ok := ce.signalSet[req]; ok {
			matchedCount++
		}
	}

	// Режим 2/3: порог совпадений
	minRequired := len(threat.Signals)
	if threat.MinMatch > 0 && threat.MinMatch < minRequired {
		minRequired = threat.MinMatch
	}

	return matchedCount >= minRequired
}

// GetFoundThreats возвращает найденные угрозы (потокобезопасная копия)
func (ce *CorrelationEngine) GetFoundThreats() []CombinationThreat {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	result := make([]CombinationThreat, len(ce.foundThreats))
	copy(result, ce.foundThreats)
	return result
}

// GetTotalRiskScore вычисляет суммарный risk score (capped at 100)
func (ce *CorrelationEngine) GetTotalRiskScore() int {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	total := 0
	for _, threat := range ce.foundThreats {
		total += threat.Risk
	}
	if total > 100 {
		total = 100
	}
	return total
}

// GetRiskBreakdown возвращает risk по категориям (riskLevel → суммарный score)
func (ce *CorrelationEngine) GetRiskBreakdown() map[string]int {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	breakdown := make(map[string]int, 4)
	for _, threat := range ce.foundThreats {
		breakdown[threat.RiskLevel] += threat.Risk
	}
	return breakdown
}

// Reset очищает состояние (переиспользует underlying arrays/maps)
func (ce *CorrelationEngine) Reset() {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.signals = ce.signals[:0]
	ce.foundThreats = ce.foundThreats[:0]
	for k := range ce.signalSet {
		delete(ce.signalSet, k)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINATION THREATS DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

func getDefaultCombinationThreats() map[string]CombinationThreat {
	return map[string]CombinationThreat{

		// ── Critical ───────────────────────────────────────────────────────

		"sms_trojan": {
			ID:   "sms_trojan",
			Name: "SMS Trojan Pattern Detected",
			Description: "Steals banking SMS messages and 2FA codes before user sees them. " +
				"One of the most dangerous mobile malware patterns. " +
				"Signals: READ_SMS + RECEIVE_BOOT_COMPLETED + INTERNET.",
			Signals:   []string{"READ_SMS", "RECEIVE_BOOT_COMPLETED", "INTERNET"},
			RiskLevel: "critical",
			Risk:      95,
			Mitigations: []string{
				"Do not install this app",
				"Use 2FA apps instead of SMS",
				"Enable installation warnings for suspicious apps",
			},
		},

		"banking_overlay": {
			ID:   "banking_overlay",
			Name: "Banking Overlay Attack Detected",
			Description: "Shows fake login screens to steal banking credentials. " +
				"The #1 mobile banking trojan technique. " +
				"Signals: BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW + INTERNET.",
			Signals:   []string{"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "INTERNET"},
			RiskLevel: "critical",
			Risk:      98,
			Mitigations: []string{
				"Remove this app immediately",
				"Change your banking password",
				"Monitor your accounts for suspicious activity",
				"Use hardware authentication if available",
			},
		},

		"banking_overlay_code": {
			ID:   "banking_overlay_code",
			Name: "Banking Overlay Code Pattern",
			Description: "Overlay window type + banking package references found in code. " +
				"Strong indicator of banking trojan even without explicit permissions.",
			Signals:   []string{"OVERLAY_TYPE_FOUND", "BANKING_PKG_REF"},
			RiskLevel: "critical",
			Risk:      90,
			Mitigations: []string{
				"Remove this app immediately",
				"Check banking accounts for unauthorized transactions",
			},
		},

		"spyware": {
			ID:   "spyware",
			Name: "Spyware/Surveillance Detected",
			Description: "Complete surveillance of user activity. " +
				"Pattern used in stalkerware and corporate espionage tools. " +
				"Requires at least 3 of: READ_SMS, CAMERA, ACCESS_FINE_LOCATION, RECORD_AUDIO.",
			Signals:   []string{"READ_SMS", "CAMERA", "ACCESS_FINE_LOCATION", "RECORD_AUDIO"},
			MinMatch:  3, // срабатывает при 3 из 4 (partial match)
			RiskLevel: "critical",
			Risk:      90,
			Mitigations: []string{
				"Remove this app",
				"Review app installation history",
				"Check account activity on associated services",
				"Consider factory reset if you suspect compromise",
			},
		},

		"device_hijacking": {
			ID:   "device_hijacking",
			Name: "Device Hijacking/Ransomware Pattern Detected",
			Description: "Lock device, display ransom message, take screenshots. " +
				"Typical of Android ransomware. " +
				"Signals: DEVICE_ADMIN + RECEIVE_BOOT_COMPLETED + INTERNET.",
			Signals:   []string{"DEVICE_ADMIN", "RECEIVE_BOOT_COMPLETED", "INTERNET"},
			RiskLevel: "critical",
			Risk:      85,
			Mitigations: []string{
				"Boot into Safe Mode and uninstall",
				"Do not contact attacker",
				"Check device from another secure device",
			},
		},

		// ── High ───────────────────────────────────────────────────────────

		"contact_exfil": {
			ID:   "contact_exfil",
			Name: "Contact/Data Exfiltration Pattern",
			Description: "Steals contacts and SMS for targeted phishing campaigns. " +
				"Signals: READ_CONTACTS + READ_SMS + INTERNET.",
			Signals:   []string{"READ_CONTACTS", "READ_SMS", "INTERNET"},
			RiskLevel: "high",
			Risk:      75,
			Mitigations: []string{
				"Remove app",
				"Review shared data",
				"Watch for phishing attempts",
			},
		},

		"screen_recorder": {
			ID:   "screen_recorder",
			Name: "Screen Recording Trojan",
			Description: "Captures screen content and sends to server. " +
				"May record banking sessions. " +
				"Signals: MEDIA_PROJECTION + INTERNET.",
			Signals:   []string{"MEDIA_PROJECTION", "INTERNET"},
			RiskLevel: "high",
			Risk:      70,
			Mitigations: []string{
				"Remove app",
				"Review recent banking activity",
				"Change passwords for accounts accessed on this device",
			},
		},

		"overlay_full_chain": {
			ID:   "overlay_full_chain",
			Name: "Full Overlay Attack Chain",
			Description: "Complete overlay attack infrastructure: " +
				"permission + overlay type + view manipulation.",
			Signals:   []string{"SYSTEM_ALERT_WINDOW", "OVERLAY_TYPE_FOUND", "OVERLAY_VIEW_MANIPULATION"},
			RiskLevel: "high",
			Risk:      80,
			Mitigations: []string{
				"Remove app",
				"Do not enter credentials while this app is installed",
			},
		},

		// ── Medium ─────────────────────────────────────────────────────────

		"permission_bloat": {
			ID:   "permission_bloat",
			Name: "Excessive Permissions",
			Description: "This app requests significantly more permissions than typical. " +
				"Could indicate capability bloat or malicious intent.",
			RiskLevel: "medium",
			Risk:      30,
			// CheckFunc: не через Signals, а через кастомную проверку
			CheckFunc: func(signals []Signal) bool {
				permCount := 0
				for i := range signals {
					if signals[i].Type == "permission" {
						permCount++
					}
				}
				return permCount >= 15
			},
			Mitigations: []string{
				"Review each permission carefully",
				"Check privacy policy",
				"Look for alternative apps with fewer permissions",
			},
		},

		"banking_target_list": {
			ID:   "banking_target_list",
			Name: "Banking App Target List",
			Description: "Code contains references to multiple banking apps " +
				"with package enumeration context. Typical target list of banking trojan.",
			Signals:   []string{"BANKING_TARGET_LIST"},
			RiskLevel: "high",
			Risk:      80,
			Mitigations: []string{
				"Remove app",
				"Monitor all banking accounts",
			},
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// GenerateCorrelationReport создаёт текстовый отчёт о корреляциях
func (ce *CorrelationEngine) GenerateCorrelationReport(threats []CombinationThreat) string {
	if len(threats) == 0 {
		return "No significant threat correlations detected.\n"
	}

	// strings.Builder вместо fmt.Sprintf + конкатенация
	var b strings.Builder
	b.Grow(len(threats) * 512) // pre-alloc estimate

	fmt.Fprintf(&b, "=== THREAT CORRELATION ANALYSIS ===\n")
	fmt.Fprintf(&b, "Total threats detected: %d\n\n", len(threats))

	totalRisk := 0
	for _, threat := range threats {
		fmt.Fprintf(&b, "🔴 %s (Risk: %d/100)\n", threat.Name, threat.Risk)
		b.WriteString("   ")
		b.WriteString(threat.Description)
		b.WriteByte('\n')

		if len(threat.Signals) > 0 {
			fmt.Fprintf(&b, "   Signals: %v\n", threat.Signals)
		}

		if len(threat.Mitigations) > 0 {
			b.WriteString("   Mitigations:\n")
			for _, mit := range threat.Mitigations {
				b.WriteString("     - ")
				b.WriteString(mit)
				b.WriteByte('\n')
			}
		}
		b.WriteByte('\n')

		totalRisk += threat.Risk
	}

	if totalRisk > 100 {
		totalRisk = 100
	}

	fmt.Fprintf(&b, "=== OVERALL RISK ASSESSMENT ===\n")
	fmt.Fprintf(&b, "Combined Risk Score: %d/100\n", totalRisk)

	switch {
	case totalRisk >= 80:
		b.WriteString("⚠️  CRITICAL: This app appears to be malicious. DO NOT INSTALL.\n")
	case totalRisk >= 60:
		b.WriteString("⚠️  HIGH RISK: Significant security concerns. Proceed with caution.\n")
	case totalRisk >= 40:
		b.WriteString("⚠️  MEDIUM RISK: Some concerning patterns detected.\n")
	}

	return b.String()
}
