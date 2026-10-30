package pipeline

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION WRAPPER FOR PIPELINE INTEGRATION
// Интегрирует Correlation Layer в основной pipeline
// ═══════════════════════════════════════════════════════════════════════════════

// CorrelationDetector оборачивает correlation engine для совместимости с interface FileDetector
type CorrelationDetector struct {
	engine *CorrelationEngine
	// Кэшируем сигналы со всех детекторов за APK
	hasRun bool
}

func NewCorrelationDetector() *CorrelationDetector {
	return &CorrelationDetector{
		engine: NewCorrelationEngine(),
		hasRun: false,
	}
}

func (d *CorrelationDetector) Name() string {
	return "correlation_detector"
}

// Detect собирает сигналы но не анализирует (нужно вызвать Finalize)
func (d *CorrelationDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// На этом этапе просто pass-through
	// Реальный анализ происходит в Finalize()
}

// Reset очищает состояние для нового APK
func (d *CorrelationDetector) Reset() {
	d.engine.Reset()
	d.hasRun = false
}

// CollectSignals собирает сигналы из найденных matches
// Должно быть вызвано после всех других детекторов
func (d *CorrelationDetector) CollectSignals(allMatches []types.Match) {
	// Преобразуем matches в сигналы для детекции
	for _, match := range allMatches {
		// Простаяя эвристика: преобразуем description в сигналы
		sig := d.matchToSignal(match)
		if sig.ID != "" {
			d.engine.AddSignal(sig)
		}
	}
}

// matchToSignal конвертирует Match в Signal
func (d *CorrelationDetector) matchToSignal(m types.Match) Signal {
	// Простой парсинг description, чтобы найти permission/api/pattern
	desc := matchDescription(m)

	// Ищем известные сигналы в description
	knownSignals := map[string]string{
		// Permissions
		"READ_SMS":                   "READ_SMS",
		"BIND_ACCESSIBILITY_SERVICE": "BIND_ACCESSIBILITY_SERVICE",
		"SYSTEM_ALERT_WINDOW":        "SYSTEM_ALERT_WINDOW",
		"RECEIVE_BOOT_COMPLETED":     "RECEIVE_BOOT_COMPLETED",
		"INTERNET":                   "INTERNET",
		"CAMERA":                     "CAMERA",
		"ACCESS_FINE_LOCATION":       "ACCESS_FINE_LOCATION",
		"RECORD_AUDIO":               "RECORD_AUDIO",
		"READ_CONTACTS":              "READ_CONTACTS",
		"DEVICE_ADMIN":               "DEVICE_ADMIN",
		"PROCESS_OUTGOING_CALLS":     "PROCESS_OUTGOING_CALLS",
		// API/Patterns
		"performGlobalAction":   "performGlobalAction",
		"AccessibilityService":  "AccessibilityService",
		"WindowManager":         "WindowManager overlay",
		"MediaProjection":       "MediaProjection",
		"SmsReceiver":           "SmsReceiver",
		"CallForwardingManager": "CallForwardingManager",
	}

	for pattern, signalID := range knownSignals {
		if containsSubstringCI(desc, pattern) {
			return Signal{
				ID:       signalID,
				Type:     "permission",
				Value:    signalID,
				Score:    d.scoreSignal(m),
				Severity: severityFromMatch(m),
				Critical: m.IsCritical,
			}
		}
	}

	return Signal{}
}

func (d *CorrelationDetector) scoreSignal(m types.Match) int {
	score := 10
	if m.IsCritical {
		score = 50
	}
	if severityFromMatch(m) >= types.SeverityHigh {
		score = 40
	}
	return score
}

// AnalyzeAndMatch выполняет корреляционный анализ
func (d *CorrelationDetector) AnalyzeAndMatch(analysis *types.FileAnalysis) {
	if d.hasRun {
		return
	}

	threats := d.engine.AnalyzeCorrelations()
	d.hasRun = true

	// Добавляем найденные угрозы в analysis
	for _, threat := range threats {
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity,
			analysis.Path,
			0,
			fmt.Sprintf("⚠️ %s (Risk Score: %d/100)", threat.Name, threat.Risk),
			threat.Description,
			threat.Risk >= 80,
		))
	}
}

// GetThreatReport генерирует текстовый отчёт о найденных угрозах
func (d *CorrelationDetector) GetThreatReport() string {
	threats := d.engine.GetFoundThreats()
	return d.engine.GenerateCorrelationReport(threats)
}

// GetTotalRiskScore возвращает итоговый risk score
func (d *CorrelationDetector) GetTotalRiskScore() int {
	return d.engine.GetTotalRiskScore()
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIPELINE INTEGRATION HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func matchDescription(m types.Match) string {
	if m.Context != "" {
		return m.Context
	}
	if m.Text != "" {
		return m.Text
	}
	return m.Pattern
}

func severityFromMatch(m types.Match) types.Severity {
	if m.IsCritical {
		return types.SeverityCritical
	}
	switch {
	case m.Score >= 9:
		return types.SeverityHigh
	case m.Score >= 7:
		return types.SeverityMedium
	case m.Score >= 4:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// containsSubstringCI проверяет подстроку без учёта регистра.
func containsSubstringCI(s, substr string) bool {
	if substr == "" {
		return false
	}
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(substr))
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE: How to integrate into Pipeline.runWorkers()
// ═══════════════════════════════════════════════════════════════════════════════

/*

// В Pipeline.Run(), после фазы анализа:

// ── Phase 2.5: Correlation Analysis ─────────────────────────────────
stage = p.tracer.StartStage("correlation")
if p.correlationDetector != nil {
	p.correlationDetector.CollectSignals(p.result.Matches)
	p.correlationDetector.AnalyzeAndMatch(p.result)
	p.result.TotalRiskScore = p.correlationDetector.GetTotalRiskScore()
	p.result.ThreatReport = p.correlationDetector.GetThreatReport()
}
p.tracer.EndStage(stage)

// Потом добавить в Pipeline структуру:
type Pipeline struct {
	// ... существующие поля ...
	correlationDetector *CorrelationDetector
}

// И инициализировать в NewPipeline:
p := &Pipeline{
	// ... другая инициализация ...
	correlationDetector: NewCorrelationDetector(),
}

*/
