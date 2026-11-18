// Package analyzer — decision_points.go v3.1
// Decision point finder with pre-compiled patterns and configurable thresholds
package analyzer

import (
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// Thresholds для конфигурации чувствительности
type DecisionPointConfig struct {
	MinConditionsForConditional int     // минимум условий для conditional DP
	MinConfidence               float64 // минимальная уверенность
}

// DefaultDecisionPointConfig значения по умолчанию
var DefaultDecisionPointConfig = DecisionPointConfig{
	MinConditionsForConditional: 2,
	MinConfidence:               0.6,
}

// Pre-compiled регулярные выражения (глобальные, не создаются каждый вызов)
var (
	constReturnFalseRe = regexp.MustCompile(`const/4\s+v\d+,\s*0x0\s*\n\s*return\s+v\d+`)
	constReturnTrueRe  = regexp.MustCompile(`const/4\s+v\d+,\s*0x1\s*\n\s*return\s+v\d+`)
	notLicensedRe      = regexp.MustCompile(`"NOT_LICENSED"`)
	purchaseFailedRe   = regexp.MustCompile(`"purchase_failed"`)
)

// DecisionPointFinder находит точки принятия решений
type DecisionPointFinder struct {
	config DecisionPointConfig
}

// NewDecisionPointFinder создаёт finder с конфигом по умолчанию.
func NewDecisionPointFinder() *DecisionPointFinder {
	return &DecisionPointFinder{
		config: DefaultDecisionPointConfig,
	}
}

// NewDecisionPointFinderWithConfig создаёт finder с кастомным конфигом.
func NewDecisionPointFinderWithConfig(cfg DecisionPointConfig) *DecisionPointFinder {
	return &DecisionPointFinder{config: cfg}
}

// FindDecisionPoints ищет точки принятия решений в методе.
func (f *DecisionPointFinder) FindDecisionPoints(
	method *types.SmaliMethod,
	className string,
	filePath string,
) []types.DecisionPoint {
	points := make([]types.DecisionPoint, 0, 4)

	// Pre-compute lowercase один раз
	nameLower := strings.ToLower(method.Name)
	classLower := strings.ToLower(className)

	// 1. Boolean return методы с подозрительными именами
	if method.ReturnsBoolean {
		if dp := f.checkBooleanMethod(method, nameLower, filePath); dp != nil {
			points = append(points, *dp)
		}
	}

	// 2. Методы с проверками и условными переходами
	if dp := f.checkConditionalMethod(method, nameLower, classLower, filePath); dp != nil {
		points = append(points, *dp)
	}

	// 3. Callback методы
	if dp := f.checkCallbackMethod(method, nameLower, filePath); dp != nil {
		points = append(points, *dp)
	}

	// 4. Void методы с анти-пиратскими названиями
	if dp := f.checkVoidAntiPiracyMethod(method, nameLower, filePath); dp != nil {
		points = append(points, *dp)
	}

	return points
}

// booleanPatterns — паттерны для boolean методов (статическая таблица)
var booleanPatterns = map[string]struct {
	category    types.Category
	description string
}{
	"islicensed":      {types.CategoryLicenseCheck, "License check"},
	"islicensevalid":  {types.CategoryLicenseCheck, "License validity"},
	"ispremium":       {types.CategoryPremiumCheck, "Premium check"},
	"ispro":           {types.CategoryPremiumCheck, "Pro check"},
	"ispaid":          {types.CategoryPremiumCheck, "Paid check"},
	"isunlocked":      {types.CategoryPremiumUnlock, "Unlock check"},
	"isfullversion":   {types.CategoryPremiumCheck, "Full version"},
	"issubscribed":    {types.CategorySubscription, "Subscription check"},
	"hassubscription": {types.CategorySubscription, "Has subscription"},
	"istrial":         {types.CategoryTrialCheck, "Trial check"},
	"istrialexpired":  {types.CategoryTrialExpiry, "Trial expired"},
	"isadfree":        {types.CategoryAdRemove, "Ad-free check"},
	"hasnoads":        {types.CategoryAdRemove, "No ads check"},
	"adsremoved":      {types.CategoryAdRemove, "Ads removed"},
	"shouldshowads":   {types.CategoryAdCheck, "Should show ads"},
	"canshowads":      {types.CategoryAdCheck, "Can show ads"},
	"isrooted":        {types.CategoryRootDetection, "Root detection"},
	"isemulator":      {types.CategoryEmulatorDetection, "Emulator detection"},
	"isdebuggable":    {types.CategoryDebugDetection, "Debug detection"},
	"istampered":      {types.CategoryTamperDetection, "Tamper detection"},
	"ismodified":      {types.CategoryTamperDetection, "Modification check"},
	"ispirated":       {types.CategoryTamperDetection, "Piracy detection"},
	"ispiracy":        {types.CategoryTamperDetection, "Piracy detection"},
	"ismoddetected":   {types.CategoryTamperDetection, "Mod detection"},
	"iscracked":       {types.CategoryTamperDetection, "Crack detection"},
	"isrepacked":      {types.CategoryTamperDetection, "Repack detection"},
	"isrepackaged":    {types.CategoryTamperDetection, "Repackage detection"},
	"isfake":          {types.CategoryTamperDetection, "Fake app detection"},
	"isunauthorized":  {types.CategoryTamperDetection, "Unauthorized use detection"},
	"isblacklisted":   {types.CategoryTamperDetection, "Blacklist detection"},
	"ispurchased":     {types.CategoryPurchaseVerify, "Purchase check"},
	"haspurchased":    {types.CategoryPurchaseVerify, "Has purchased"},
	"isexpired":       {types.CategoryTiming, "Expiry check"},
}

func (f *DecisionPointFinder) checkBooleanMethod(
	method *types.SmaliMethod,
	nameLower string,
	filePath string,
) *types.DecisionPoint {
	for pattern, info := range booleanPatterns {
		// Short names must match entitlement/app predicates, not UI/storage
		// names such as isProjected, isProperSDFolder or isFakeDragging.
		if pattern == "ispro" && nameLower != "ispro" && nameLower != "isprouser" && nameLower != "isproversion" && nameLower != "isproactive" {
			continue
		}
		if pattern == "isfake" && nameLower != "isfake" && nameLower != "isfakeapp" && nameLower != "isfakeapk" {
			continue
		}
		if strings.Contains(nameLower, pattern) {
			return &types.DecisionPoint{
				SourceLocation: types.SourceLocation{File: filePath, Line: method.LineStart},
				Scored:         types.Scored{Confidence: 0.9},
				Method:         method.Name,
				Type:           types.DecisionBooleanReturn,
				Category:       info.category,
				Description:    info.description + " method: " + method.Name,
			}
		}
	}
	return nil
}

// checkPatterns для conditional методов
var checkPatterns = []string{"check", "verify", "validate", "ensure"}

func (f *DecisionPointFinder) checkConditionalMethod(
	method *types.SmaliMethod,
	nameLower, classLower string,
	filePath string,
) *types.DecisionPoint {
	if len(method.Conditions) < f.config.MinConditionsForConditional {
		return nil
	}

	for _, pattern := range checkPatterns {
		if !strings.Contains(nameLower, pattern) {
			continue
		}

		// Определяем категорию по контексту
		category := f.detectCategoryFromContext(nameLower, classLower)
		if category == types.CategoryUnknown {
			continue
		}

		return &types.DecisionPoint{
			SourceLocation: types.SourceLocation{File: filePath, Line: method.LineStart},
			Scored:         types.Scored{Confidence: 0.7},
			Method:         method.Name,
			Type:           types.DecisionConditional,
			Category:       category,
			Description:    "Conditional check method: " + method.Name,
		}
	}

	return nil
}

// detectCategoryFromContext определяет категорию из контекста имён.
func (f *DecisionPointFinder) detectCategoryFromContext(nameLower, classLower string) types.Category {
	combined := nameLower + " " + classLower

	switch {
	case strings.Contains(combined, "license"):
		return types.CategoryLicenseCheck
	case strings.Contains(combined, "premium"):
		return types.CategoryPremiumCheck
	case strings.Contains(combined, "purchase"):
		return types.CategoryPurchaseVerify
	case strings.Contains(combined, "signature"):
		return types.CategorySignatureCheck
	case strings.Contains(combined, "piracy") || strings.Contains(combined, "pirat") ||
		strings.Contains(combined, "modded") || strings.Contains(combined, "moddet") ||
		strings.Contains(combined, "crack") || strings.Contains(combined, "repack") ||
		strings.Contains(combined, "tamper"):
		return types.CategoryTamperDetection
	default:
		return types.CategoryUnknown
	}
}

// callbackPatterns для callback методов
var callbackPatterns = map[string]struct {
	category types.Category
	desc     string
}{
	"dontallow":              {types.CategoryGoogleLVL, "LVL dontAllow callback"},
	"applicationerror":       {types.CategoryGoogleLVL, "LVL applicationError callback"},
	"onpurchasesupdated":     {types.CategoryBillingCallback, "Billing purchase callback"},
	"onbillingsetupfinished": {types.CategoryBillingCallback, "Billing setup callback"},
	"onlicensechecked":       {types.CategoryLicenseCallback, "License checked callback"},
	"onlicenseerror":         {types.CategoryLicenseCallback, "License error callback"},
}

func (f *DecisionPointFinder) checkCallbackMethod(
	method *types.SmaliMethod,
	nameLower string,
	filePath string,
) *types.DecisionPoint {
	for pattern, info := range callbackPatterns {
		if strings.Contains(nameLower, pattern) {
			return &types.DecisionPoint{
				SourceLocation: types.SourceLocation{File: filePath, Line: method.LineStart},
				Scored:         types.Scored{Confidence: 0.95},
				Method:         method.Name,
				Type:           types.DecisionCallback,
				Category:       info.category,
				Description:    info.desc,
			}
		}
	}
	return nil
}

// antiPiracyKeywords для void методов
var antiPiracyKeywords = []string{
	"piracy", "pirat", "modded", "moddet", "crack", "repack", "tamper", "blacklist",
}

func (f *DecisionPointFinder) checkVoidAntiPiracyMethod(
	method *types.SmaliMethod,
	nameLower string,
	filePath string,
) *types.DecisionPoint {
	if method.ReturnType != "V" {
		return nil
	}

	for _, kw := range antiPiracyKeywords {
		if strings.Contains(nameLower, kw) {
			return &types.DecisionPoint{
				SourceLocation: types.SourceLocation{File: filePath, Line: method.LineStart},
				Scored:         types.Scored{Confidence: 0.85},
				Method:         method.Name,
				Type:           types.DecisionUnknown,
				Category:       types.CategoryTamperDetection,
				Description:    "Anti-piracy screen/handler method: " + method.Name,
			}
		}
	}

	return nil
}

// bodyPatterns для поиска в теле метода
var bodyPatterns = []struct {
	re       *regexp.Regexp
	category types.Category
	desc     string
}{
	{constReturnFalseRe, types.CategoryLicenseCheck, "Returns false (potential license check)"},
	{notLicensedRe, types.CategoryGoogleLVL, "NOT_LICENSED constant"},
	{purchaseFailedRe, types.CategoryPurchaseVerify, "Purchase failed handling"},
}

// FindInBody ищет паттерны в теле метода.
// Использует предкомпилированные regex.
func (f *DecisionPointFinder) FindInBody(method *types.SmaliMethod, body string) []types.DecisionPoint {
	points := make([]types.DecisionPoint, 0, 2)

	for _, p := range bodyPatterns {
		if loc := p.re.FindStringIndex(body); loc != nil {
			// Вычисляем примерный номер строки
			lineNum := method.LineStart + strings.Count(body[:loc[0]], "\n")

			points = append(points, types.DecisionPoint{
				SourceLocation: types.SourceLocation{
					File: "", // будет заполнен вызывающим кодом
					Line: lineNum,
				},
				Scored:      types.Scored{Confidence: 0.8},
				Method:      method.Name,
				Type:        types.DecisionUnknown,
				Category:    p.category,
				Description: p.desc,
			})
		}
	}

	return points
}

// FindInBodyBytes ищет паттерны используя предвычисленное тело.
// Более эффективная версия для когда body уже разобран.
func (f *DecisionPointFinder) FindInBodyBytes(method *types.SmaliMethod) []types.DecisionPoint {
	if len(method.Body) == 0 {
		return nil
	}

	// Объединяем body для regex поиска
	body := strings.Join(method.Body, "\n")
	return f.FindInBody(method, body)
}
