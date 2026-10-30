package ml

import (
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT SCORER — движок контекстно-зависимого скоринга
// ═══════════════════════════════════════════════════════════════════════════════

// ContextScorer — движок для подсчёта очков с учётом контекста приложения
type ContextScorer struct {
	rules *ContextRules
}

// NewContextScorer создаёт новый scorer с правилами
func NewContextScorer(rules *ContextRules) *ContextScorer {
	if rules == nil {
		rules = NewContextRules()
	}
	return &ContextScorer{rules: rules}
}

// NewDefaultContextScorer создаёт scorer с дефолтными правилами
func NewDefaultContextScorer() *ContextScorer {
	return NewContextScorer(NewContextRules())
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING RESULT — результат скоринга
// ═══════════════════════════════════════════════════════════════════════════════

// ContextScoringResult — полный результат контекстного скоринга
type ContextScoringResult struct {
	AppContext *AppContext `json:"app_context"`

	TotalScore      int             `json:"total_score"`
	ThreatLevel     ThreatLevel     `json:"threat_level"`
	ThreatLevelInfo ThreatLevelInfo `json:"threat_level_info"`

	SignalBreakdown []SignalBreakdownItem `json:"signal_breakdown"`
	SignalScore     int                   `json:"signal_score"`

	MatchedCombos []MatchedCombo `json:"matched_combos,omitempty"`
	ComboScore    int            `json:"combo_score"`

	TypeBias int `json:"type_bias"`

	Summary         string   `json:"summary"`
	Explanations    []string `json:"explanations,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
	Threats         []string `json:"threats,omitempty"`
}

// SignalBreakdownItem — детализация очков по сигналу
type SignalBreakdownItem struct {
	Signal      string `json:"signal"`
	Description string `json:"description,omitempty"`
	BasePoints  int    `json:"base_points"`
	ContextMod  int    `json:"context_mod"`
	FinalPoints int    `json:"final_points"`
	Category    string `json:"category,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// MatchedCombo — совпавшая комбинация
type MatchedCombo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Signals     []string `json:"signals"`
	BonusPoints int      `json:"bonus_points"`
	ThreatName  string   `json:"threat_name,omitempty"`
	ThreatType  string   `json:"threat_type,omitempty"`
	Severity    string   `json:"severity"`
	MITRE       string   `json:"mitre,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN SCORING METHOD
// ═══════════════════════════════════════════════════════════════════════════════

// Score вычисляет полный скор для приложения
func (cs *ContextScorer) Score(ctx *AppContext) *ContextScoringResult {
	if ctx == nil {
		return &ContextScoringResult{
			ThreatLevel: ThreatNone,
			Summary:     "No context provided",
		}
	}

	result := &ContextScoringResult{
		AppContext:      ctx,
		SignalBreakdown: make([]SignalBreakdownItem, 0, len(ctx.DetectedSignals)),
		MatchedCombos:   make([]MatchedCombo, 0),
		Explanations:    make([]string, 0),
		Recommendations: make([]string, 0),
		Threats:         make([]string, 0),
	}

	result.SignalScore = cs.scoreSignals(ctx, result)
	result.ComboScore = cs.scoreCombos(ctx, result)
	result.TypeBias = ctx.GetRiskBias()

	result.TotalScore = result.SignalScore + result.ComboScore + result.TypeBias
	if result.TotalScore < 0 {
		result.TotalScore = 0
	}

	result.ThreatLevel = cs.rules.Thresholds.GetLevel(result.TotalScore)
	result.ThreatLevelInfo = GetThreatLevelInfo(result.ThreatLevel)

	cs.generateExplanations(result)
	cs.generateRecommendations(result)
	result.Summary = cs.generateSummary(result)

	return result
}

// ScoreSignals вычисляет очки только по сигналам
func (cs *ContextScorer) ScoreSignals(signals []string, appType AppType) int {
	total := 0
	for _, signal := range signals {
		rule := cs.rules.GetSignalRule(signal)
		_, _, points := rule.GetPoints(appType)
		total += points
	}
	return total
}

func (cs *ContextScorer) scoreSignals(ctx *AppContext, result *ContextScoringResult) int {
	totalScore := 0

	for _, signal := range ctx.DetectedSignals {
		rule := cs.rules.GetSignalRule(signal)
		base, mod, final := rule.GetPoints(ctx.DetectedType)

		item := SignalBreakdownItem{
			Signal:      signal,
			Description: rule.Description,
			BasePoints:  base,
			ContextMod:  mod,
			FinalPoints: final,
			Category:    string(rule.Category),
		}

		if mod != 0 {
			item.Reason = cs.getModReason(signal, ctx.DetectedType, mod)
		}

		result.SignalBreakdown = append(result.SignalBreakdown, item)
		totalScore += final
	}

	sort.Slice(result.SignalBreakdown, func(i, j int) bool {
		return result.SignalBreakdown[i].FinalPoints > result.SignalBreakdown[j].FinalPoints
	})

	return totalScore
}

func (cs *ContextScorer) getModReason(_ string, appType AppType, mod int) string {
	typeInfo := GetAppTypeInfo(appType)

	if mod > 0 {
		switch {
		case appType == AppTypeBanking || appType == AppTypePayment || appType == AppTypeCrypto:
			return fmt.Sprintf("+%d: critical for %s apps", mod, typeInfo.DisplayName)
		case appType == AppTypeMalware:
			return fmt.Sprintf("+%d: confirms malware behavior", mod)
		default:
			return fmt.Sprintf("+%d: suspicious for %s", mod, typeInfo.DisplayName)
		}
	} else {
		switch {
		case appType == AppTypeAccessibility:
			return fmt.Sprintf("%d: legitimate for accessibility apps", mod)
		case appType == AppTypeSecurity:
			return fmt.Sprintf("%d: expected for security apps", mod)
		case appType == AppTypeLauncher:
			return fmt.Sprintf("%d: common for launcher apps", mod)
		default:
			return fmt.Sprintf("%d: acceptable for %s", mod, typeInfo.DisplayName)
		}
	}
}

func (cs *ContextScorer) scoreCombos(ctx *AppContext, result *ContextScoringResult) int {
	totalScore := 0
	matchedCombos := cs.rules.FindMatchingCombos(ctx.DetectedSignals)

	for _, combo := range matchedCombos {
		matched := MatchedCombo{
			Name:        combo.Name,
			Description: combo.Description,
			Signals:     combo.Signals,
			BonusPoints: combo.BonusPoints,
			ThreatName:  combo.ThreatName,
			ThreatType:  combo.ThreatType,
			Severity:    combo.Severity,
			MITRE:       combo.MITRE,
		}

		result.MatchedCombos = append(result.MatchedCombos, matched)
		totalScore += combo.BonusPoints

		if combo.ThreatName != "" {
			result.Threats = append(result.Threats, combo.ThreatName)
		}

		ctx.AddCombo(DetectedCombo{
			Name:       combo.Name,
			Signals:    combo.Signals,
			ThreatType: combo.ThreatType,
			Severity:   combo.Severity,
		})
	}

	sort.Slice(result.MatchedCombos, func(i, j int) bool {
		sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		si, sj := sevOrder[result.MatchedCombos[i].Severity], sevOrder[result.MatchedCombos[j].Severity]
		if si != sj {
			return si < sj
		}
		return result.MatchedCombos[i].BonusPoints > result.MatchedCombos[j].BonusPoints
	})

	return totalScore
}

func (cs *ContextScorer) generateExplanations(result *ContextScoringResult) {
	ctx := result.AppContext
	typeInfo := GetAppTypeInfo(ctx.DetectedType)

	if ctx.TypeConfidence > 0.5 {
		result.Explanations = append(result.Explanations,
			fmt.Sprintf("Detected as %s %s app (confidence: %.0f%%)",
				typeInfo.Icon, typeInfo.DisplayName, ctx.TypeConfidence*100))
	}

	for _, combo := range result.MatchedCombos {
		icon := "⚠️"
		switch combo.Severity {
		case "critical":
			icon = "🚨"
		case "high":
			icon = "🔴"
		}

		explanation := fmt.Sprintf("%s %s: %s (+%d points)",
			icon, combo.ThreatName, combo.Description, combo.BonusPoints)
		result.Explanations = append(result.Explanations, explanation)

		if combo.MITRE != "" {
			result.Explanations = append(result.Explanations,
				fmt.Sprintf("   MITRE ATT&CK: %s", combo.MITRE))
		}
	}

	dangerousSignals := 0
	for _, item := range result.SignalBreakdown {
		if item.FinalPoints >= 10 && dangerousSignals < 3 {
			result.Explanations = append(result.Explanations,
				fmt.Sprintf("⚡ %s: %s (%+d points)",
					item.Signal, item.Description, item.FinalPoints))
			dangerousSignals++
		}
	}

	if result.TypeBias != 0 {
		if result.TypeBias > 0 {
			result.Explanations = append(result.Explanations,
				fmt.Sprintf("📊 Type bias: +%d (threats more critical for %s apps)",
					result.TypeBias, typeInfo.DisplayName))
		} else {
			result.Explanations = append(result.Explanations,
				fmt.Sprintf("📊 Type bias: %d (some behaviors expected for %s apps)",
					result.TypeBias, typeInfo.DisplayName))
		}
	}
}

func (cs *ContextScorer) generateRecommendations(result *ContextScoringResult) {
	ctx := result.AppContext

	switch result.ThreatLevel {
	case ThreatCritical:
		result.Recommendations = append(result.Recommendations,
			"🚨 CRITICAL: Do not install this application")
		result.Recommendations = append(result.Recommendations,
			"🚨 If installed, remove immediately and check for data breach")
		if ctx.IsFinancial() {
			result.Recommendations = append(result.Recommendations,
				"🏦 Check your financial accounts for unauthorized activity")
		}

	case ThreatHigh:
		result.Recommendations = append(result.Recommendations,
			"🔴 HIGH RISK: Installation not recommended")
		result.Recommendations = append(result.Recommendations,
			"🔴 If you must install, use isolated environment")

	case ThreatMedium:
		result.Recommendations = append(result.Recommendations,
			"🟡 MEDIUM RISK: Review permissions before installing")
		result.Recommendations = append(result.Recommendations,
			"🟡 Monitor app behavior after installation")

	case ThreatLow:
		result.Recommendations = append(result.Recommendations,
			"🟢 LOW RISK: Normal caution advised")
	}

	for _, combo := range result.MatchedCombos {
		switch combo.Name {
		case "trojan_overlay_admin":
			result.Recommendations = append(result.Recommendations,
				"⛔ Classic banking trojan pattern detected - DO NOT INSTALL")
		case "banking_stealer":
			result.Recommendations = append(result.Recommendations,
				"⛔ Banking credentials stealer pattern - change passwords if installed")
		case "sms_stealer":
			result.Recommendations = append(result.Recommendations,
				"⛔ SMS interception capability - check for unauthorized messages")
		case "otp_stealer":
			result.Recommendations = append(result.Recommendations,
				"⛔ OTP interception pattern - enable hardware 2FA if possible")
		}
	}

	if ctx.IsLegitimateAccessibilityUser() && ctx.PermFlags.Has(PermAccessibility) {
		if result.ThreatLevel <= ThreatMedium {
			result.Recommendations = append(result.Recommendations,
				"ℹ️ Accessibility service usage appears legitimate for this app type")
		}
	}
}

func (cs *ContextScorer) generateSummary(result *ContextScoringResult) string {
	ctx := result.AppContext
	typeInfo := GetAppTypeInfo(ctx.DetectedType)
	threatInfo := result.ThreatLevelInfo

	parts := []string{
		fmt.Sprintf("%s %s Risk", threatInfo.Icon, threatInfo.DisplayName),
		fmt.Sprintf("Score: %d", result.TotalScore),
	}

	if ctx.TypeConfidence > 0.3 {
		parts = append(parts, fmt.Sprintf("Type: %s %s", typeInfo.Icon, typeInfo.DisplayName))
	}

	if len(result.MatchedCombos) > 0 {
		parts = append(parts, fmt.Sprintf("Combos: %d", len(result.MatchedCombos)))
	}

	if len(result.Threats) > 0 {
		parts = append(parts, fmt.Sprintf("Threats: %s", strings.Join(result.Threats, ", ")))
	}

	return strings.Join(parts, " | ")
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUICK METHODS
// ═══════════════════════════════════════════════════════════════════════════════

// QuickScore быстро вычисляет скор без полного breakdown
func (cs *ContextScorer) QuickScore(signals []string, appType AppType) (score int, level ThreatLevel) {
	score = cs.ScoreSignals(signals, appType)

	combos := cs.rules.FindMatchingCombos(signals)
	for _, combo := range combos {
		score += combo.BonusPoints
	}

	score += GetAppTypeInfo(appType).RiskBias

	if score < 0 {
		score = 0
	}

	level = cs.rules.Thresholds.GetLevel(score)
	return score, level
}

// IsHighRisk быстро проверяет, является ли приложение высокорисковым
func (cs *ContextScorer) IsHighRisk(ctx *AppContext) bool {
	if ctx == nil {
		return false
	}

	_, level := cs.QuickScore(ctx.DetectedSignals, ctx.DetectedType)
	// High risk includes both high and critical threat levels
	return level == ThreatHigh || level == ThreatCritical
}

// IsCritical быстро проверяет критический уровень
func (cs *ContextScorer) IsCritical(ctx *AppContext) bool {
	score, _ := cs.QuickScore(ctx.DetectedSignals, ctx.DetectedType)
	return score >= cs.rules.Thresholds.Critical
}

// HasDangerousCombos проверяет наличие опасных комбинаций
func (cs *ContextScorer) HasDangerousCombos(signals []string) bool {
	combos := cs.rules.FindMatchingCombos(signals)
	for _, combo := range combos {
		if combo.Severity == "critical" || combo.Severity == "high" {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPARISON & ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// CompareAppTypes сравнивает скоры одних и тех же сигналов для разных типов
func (cs *ContextScorer) CompareAppTypes(signals []string) map[AppType]int {
	result := make(map[AppType]int)
	for _, appType := range AllAppTypes() {
		score, _ := cs.QuickScore(signals, appType)
		result[appType] = score
	}
	return result
}

// GetSignalImpact возвращает impact сигнала для разных типов
func (cs *ContextScorer) GetSignalImpact(signal string) map[AppType]int {
	rule := cs.rules.GetSignalRule(signal)
	result := make(map[AppType]int)

	for _, appType := range AllAppTypes() {
		_, _, total := rule.GetPoints(appType)
		result[appType] = total
	}

	return result
}

// FindMostDangerousSignals возвращает самые опасные сигналы для контекста
func (cs *ContextScorer) FindMostDangerousSignals(ctx *AppContext, n int) []SignalBreakdownItem {
	result := cs.Score(ctx)

	if len(result.SignalBreakdown) <= n {
		return result.SignalBreakdown
	}

	return result.SignalBreakdown[:n]
}

// ═══════════════════════════════════════════════════════════════════════════════
// FORMATTING
// ═══════════════════════════════════════════════════════════════════════════════

// FormatResult форматирует результат для вывода
func (cs *ContextScorer) FormatResult(result *ContextScoringResult) string {
	var sb strings.Builder

	threatInfo := result.ThreatLevelInfo

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║              CONTEXT-AWARE THREAT ANALYSIS                   ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("  %s THREAT LEVEL: %s\n", threatInfo.Icon, strings.ToUpper(string(result.ThreatLevel))))
	sb.WriteString(fmt.Sprintf("  Total Score: %d points\n", result.TotalScore))
	sb.WriteString("\n")

	if result.AppContext != nil {
		ctx := result.AppContext
		typeInfo := GetAppTypeInfo(ctx.DetectedType)
		sb.WriteString("  App Context:\n")
		sb.WriteString("  ─────────────\n")
		sb.WriteString(fmt.Sprintf("    Package:    %s\n", ctx.PackageName))
		sb.WriteString(fmt.Sprintf("    Type:       %s %s (%.0f%% confidence)\n",
			typeInfo.Icon, typeInfo.DisplayName, ctx.TypeConfidence*100))
		sb.WriteString(fmt.Sprintf("    Signals:    %d detected\n", len(ctx.DetectedSignals)))
		sb.WriteString(fmt.Sprintf("    Dangerous:  %d permissions\n", ctx.DangerousPerms))
		sb.WriteString("\n")
	}

	if len(result.SignalBreakdown) > 0 {
		sb.WriteString("  Signal Breakdown:\n")
		sb.WriteString("  ─────────────────\n")
		for _, item := range result.SignalBreakdown {
			modStr := ""
			if item.ContextMod != 0 {
				modStr = fmt.Sprintf(" %+d", item.ContextMod)
			}
			sb.WriteString(fmt.Sprintf("    %-25s %3d base%s = %3d\n",
				item.Signal+":", item.BasePoints, modStr, item.FinalPoints))
		}
		sb.WriteString(fmt.Sprintf("    %-25s         = %3d\n", "Signal subtotal:", result.SignalScore))
		sb.WriteString("\n")
	}

	if len(result.MatchedCombos) > 0 {
		sb.WriteString("  🔥 Dangerous Combinations:\n")
		sb.WriteString("  ──────────────────────────\n")
		for _, combo := range result.MatchedCombos {
			icon := "⚠️"
			switch combo.Severity {
			case "critical":
				icon = "🚨"
			case "high":
				icon = "🔴"
			}
			sb.WriteString(fmt.Sprintf("    %s %s (+%d)\n", icon, combo.ThreatName, combo.BonusPoints))
			sb.WriteString(fmt.Sprintf("       Signals: %s\n", strings.Join(combo.Signals, " + ")))
			if combo.MITRE != "" {
				sb.WriteString(fmt.Sprintf("       MITRE: %s\n", combo.MITRE))
			}
		}
		sb.WriteString(fmt.Sprintf("    %-25s         = %3d\n", "Combo bonus:", result.ComboScore))
		sb.WriteString("\n")
	}

	if result.TypeBias != 0 {
		sb.WriteString(fmt.Sprintf("  Type Bias: %+d\n\n", result.TypeBias))
	}

	if len(result.Threats) > 0 {
		sb.WriteString("  ☠️ Detected Threats:\n")
		sb.WriteString("  ────────────────────\n")
		for _, threat := range result.Threats {
			sb.WriteString(fmt.Sprintf("    • %s\n", threat))
		}
		sb.WriteString("\n")
	}

	if len(result.Recommendations) > 0 {
		sb.WriteString("  📋 Recommendations:\n")
		sb.WriteString("  ───────────────────\n")
		for _, rec := range result.Recommendations {
			sb.WriteString(fmt.Sprintf("    %s\n", rec))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// FormatCompact возвращает компактный формат
func (cs *ContextScorer) FormatCompact(result *ContextScoringResult) string {
	threatInfo := result.ThreatLevelInfo
	threats := ""
	if len(result.Threats) > 0 {
		threats = " [" + strings.Join(result.Threats, ", ") + "]"
	}
	return fmt.Sprintf("%s %s (%d pts)%s",
		threatInfo.Icon, threatInfo.DisplayName, result.TotalScore, threats)
}
