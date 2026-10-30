package ml

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY-AWARE RISK THRESHOLDS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Проблема глобальных порогов (High=65 / Medium=45 / Low=30): один и тот же
// cutoff применяется к высокосигнальному, низкошумному гейту (root/license/
// premium/currency) И к шумной категории (ads/analytics). Это одновременно:
//   • режет recall на именно тех проверках, которые нам нужны (сильный, но
//     чуть-чуть не дотянувший до 65 license-гейт остаётся MEDIUM/скрытым);
//   • раздувает precision-риск на рекламе (ad-шум легко перескакивает 30).
//
// Категорийные пороги решают обе задачи разом:
//   • для доверенных категорий порог СНИЖЕН → больше находок (recall↑);
//   • для шумных категорий порог ПОВЫШЕН → меньше ложных (precision↑).
//
// Для категорий без override поведение идентично глобальному RiskLevelFromScore
// (полная обратная совместимость).

// CategoryThresholds — тройка порогов классификации для одной категории.
type CategoryThresholds struct {
	High   float64
	Medium float64
	Low    float64
}

// categoryThresholdOverrides — только явно настроенные категории. Значения
// подобраны относительно глобальных 65/45/30: «доверенные» ниже, «шумные» выше.
var categoryThresholdOverrides = map[PatchCategory]CategoryThresholds{
	// ── Высокий сигнал / низкий шум: снижаем порог, ловим больше ──────────────
	PatchCatLicense:      {High: 55, Medium: 38, Low: 24},
	PatchCatBilling:      {High: 55, Medium: 38, Low: 24},
	PatchCatPremium:      {High: 55, Medium: 38, Low: 24},
	PatchCatSubscription: {High: 55, Medium: 38, Low: 24},
	PatchCatFeatureGate:  {High: 55, Medium: 38, Low: 24},
	PatchCatTrialExpiry:  {High: 55, Medium: 38, Low: 24},
	// Игровая экономика — главный фокус: самый низкий порог (максимум находок).
	PatchCatCurrency: {High: 52, Medium: 35, Low: 22},

	// ── Детекторы среды/целостности: чуть ниже глобального, но осторожнее ─────
	PatchCatRootDetect:    {High: 55, Medium: 38, Low: 24},
	PatchCatEmulatorCheck: {High: 55, Medium: 38, Low: 24},
	PatchCatDebugDetect:   {High: 55, Medium: 38, Low: 24},
	PatchCatHookDetect:    {High: 58, Medium: 40, Low: 26},
	PatchCatTamper:        {High: 58, Medium: 40, Low: 26},
	PatchCatSignature:     {High: 58, Medium: 40, Low: 26},
	PatchCatIntegrity:     {High: 58, Medium: 40, Low: 26},
	PatchCatSSLPinning:    {High: 58, Medium: 40, Low: 26},
	PatchCatDRM:           {High: 58, Medium: 40, Low: 26},
	PatchCatServerAuth:    {High: 58, Medium: 40, Low: 26},
	PatchCatJWTForge:      {High: 58, Medium: 40, Low: 26},

	// ── Шумные категории: повышаем порог, режем ложные срабатывания ───────────
	PatchCatAds:       {High: 72, Medium: 55, Low: 40},
	PatchCatAnalytics: {High: 75, Medium: 58, Low: 44},
}

// ThresholdsForCategory возвращает пороги для категории. Для категории без
// override — глобальные High/Medium/LowRiskThreshold.
func ThresholdsForCategory(cat PatchCategory) CategoryThresholds {
	if t, ok := categoryThresholdOverrides[cat]; ok {
		return t
	}
	return CategoryThresholds{
		High:   HighRiskThreshold,
		Medium: MediumRiskThreshold,
		Low:    LowRiskThreshold,
	}
}

// RiskLevelForCategory классифицирует score с учётом категории. Для неизвестной
// или пустой категории результат ИДЕНТИЧЕН RiskLevelFromScore — обратная
// совместимость гарантирована.
func RiskLevelForCategory(cat PatchCategory, score float64) RiskClass {
	t := ThresholdsForCategory(cat)
	switch {
	case score >= t.High:
		return RiskClassHigh
	case score >= t.Medium:
		return RiskClassMedium
	case score >= t.Low:
		return RiskClassLow
	default:
		return RiskClassNone
	}
}
