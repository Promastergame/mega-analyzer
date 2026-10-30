// Package verdict превращает итог анализа в код возврата процесса для CI.
//
// Главная идея — различать «ничего не нашли» и «не смогли посмотреть». Скан,
// в котором часть файлов не разобралась, сработал лимит или набор правил
// оказался урезан, не доказывает, что образец чист, поэтому такой запуск не
// должен выглядеть как код 0.
//
//	0  чисто
//	1  найдено на уровне -fail-on и выше (по умолчанию critical)
//	2  найдено на ступень ниже (по умолчанию high)
//	3  ошибка запуска
//	4  анализ неполный: результат «чисто/подозрительно» ничего не доказывает
//
// Приоритет: 1 > 4 > 2 > 0. Находка нужного уровня остаётся в силе даже при
// неполном анализе (недостающие проверки могли только добавить находок), а вот
// «чисто» и «подозрительно» при неполном анализе превращаются в 4.
package verdict

import (
	"fmt"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

// Code — код возврата процесса.
type Code int

const (
	Clean      Code = 0
	Hostile    Code = 1
	Suspicious Code = 2
	Error      Code = 3
	Incomplete Code = 4
)

func (c Code) String() string {
	switch c {
	case Clean:
		return "clean"
	case Hostile:
		return "findings-at-fail-level"
	case Suspicious:
		return "findings-below-fail-level"
	case Error:
		return "error"
	case Incomplete:
		return "incomplete"
	default:
		return fmt.Sprintf("code-%d", int(c))
	}
}

// ParseFailOn разбирает значение флага -fail-on.
func ParseFailOn(s string) (types.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "critical":
		return types.SeverityCritical, nil
	case "high":
		return types.SeverityHigh, nil
	case "medium":
		return types.SeverityMedium, nil
	case "low":
		return types.SeverityLow, nil
	}
	return 0, fmt.Errorf("invalid -fail-on %q (use critical, high, medium or low)", s)
}

// Options настраивает оценку.
type Options struct {
	// FailOn — нижняя граница для кода 1. Ноль (info) трактуется как critical.
	FailOn types.Severity
	// Interrupted — запуск прерван пользователем (Ctrl+C / SIGTERM).
	Interrupted bool
}

// Assessment — итог оценки.
type Assessment struct {
	Code        Code
	MaxSeverity types.Severity
	HasFindings bool
	// Incomplete — причины неполноты анализа (пусто, если анализ полный).
	Incomplete []string
}

// Summary — короткая строка для stderr.
func (a Assessment) Summary() string {
	s := fmt.Sprintf("exit status %d (%s)", int(a.Code), a.Code)
	if len(a.Incomplete) > 0 {
		s += ": " + strings.Join(a.Incomplete, "; ")
	}
	return s
}

// Assess считает итог по результату анализа и накопленным деградациям.
func Assess(res *types.AnalysisResult, opt Options) Assessment {
	failOn := opt.FailOn
	if failOn == types.SeverityInfo {
		failOn = types.SeverityCritical
	}
	warnOn := failOn - 1

	var a Assessment
	if res == nil {
		a.Code = Error
		return a
	}

	a.MaxSeverity, a.HasFindings = maxSeverity(res)
	a.Incomplete = incompleteReasons(res, opt)

	switch {
	case a.HasFindings && a.MaxSeverity >= failOn:
		a.Code = Hostile
	case len(a.Incomplete) > 0:
		a.Code = Incomplete
	case a.HasFindings && a.MaxSeverity >= warnOn:
		a.Code = Suspicious
	default:
		a.Code = Clean
	}
	return a
}

func maxSeverity(res *types.AnalysisResult) (types.Severity, bool) {
	var best types.Severity
	found := false
	bump := func(s types.Severity) {
		if !found || s > best {
			best = s
		}
		found = true
	}

	if res.Stats.CriticalMatches > 0 {
		bump(types.SeverityCritical)
	}
	for i := range res.RuleMatches {
		bump(res.RuleMatches[i].Severity)
	}
	for _, fa := range res.Files {
		if fa == nil {
			continue
		}
		for i := range fa.Matches {
			bump(fa.Matches[i].Severity)
		}
	}
	for i := range res.Findings {
		if s, ok := parseSeverity(res.Findings[i]); ok {
			bump(s)
		}
	}
	return best, found
}

func parseSeverity(f finding.Finding) (types.Severity, bool) {
	switch strings.ToLower(f.Severity) {
	case "critical":
		return types.SeverityCritical, true
	case "high":
		return types.SeverityHigh, true
	case "medium", "warning":
		return types.SeverityMedium, true
	case "low":
		return types.SeverityLow, true
	case "info", "note":
		return types.SeverityInfo, true
	}
	return 0, false
}

// incompleteReasons перечисляет всё, из-за чего вердикт «чисто» нельзя считать
// доказанным. Явный статус неполноты, в том числе от дополнительных стадий,
// имеет ту же силу, что и счётчики покрытия основного конвейера.
func incompleteReasons(res *types.AnalysisResult, opt Options) []string {
	var out []string
	if res.Run != nil && incompleteStatus(res.Run.Status) {
		reason := "run incomplete"
		if res.Run.StopReason != "" {
			reason += ": " + res.Run.StopReason
		}
		out = append(out, reason)
	}
	if res.BundleAnalysis != nil && incompleteStatus(res.BundleAnalysis.Status) {
		out = append(out, "bundle analysis "+res.BundleAnalysis.Status)
	}
	for _, stage := range res.StaticOutputs {
		if incompleteStatus(stage.Status) {
			out = append(out, "static output "+stage.Stage+": "+stage.Status)
		}
	}
	c := res.Coverage
	if c.ParseFailed > 0 {
		out = append(out, fmt.Sprintf("%d file(s) failed to parse", c.ParseFailed))
	}
	if c.FilesFailed > 0 {
		out = append(out, fmt.Sprintf("%d file(s) failed during analysis", c.FilesFailed))
	}
	if c.LimitReached || c.SkippedByLimit > 0 {
		out = append(out, fmt.Sprintf("analysis limit reached (%d file(s) skipped)", c.SkippedByLimit))
	}
	df := res.DataFlowStats
	if df.Cancelled {
		out = append(out, "data-flow analysis cancelled")
	}
	if df.MethodsTruncated > 0 {
		out = append(out, fmt.Sprintf("%d method(s) skipped by data-flow limits", df.MethodsTruncated))
	}
	if df.SliceLimitReached || df.SlicesTruncated > 0 {
		out = append(out, fmt.Sprintf("data-flow slicing limit reached (%d slice(s) truncated)", df.SlicesTruncated))
	}
	if df.CFGIncompleteMethods > 0 {
		out = append(out, fmt.Sprintf("%d method(s) have incomplete control-flow graphs", df.CFGIncompleteMethods))
	}
	if df.LimitReached && !df.Cancelled && df.MethodsTruncated == 0 && !df.SliceLimitReached && df.SlicesTruncated == 0 && df.CFGIncompleteMethods == 0 {
		out = append(out, "data-flow analysis limit reached")
	}
	if res.Stats.TotalFiles > 0 && res.Stats.AnalyzedFiles == 0 && c.AnalyzedClasses == 0 {
		out = append(out, "no file was analyzed")
	}
	if opt.Interrupted {
		out = append(out, "interrupted before completion")
	}
	out = append(out, Degradations()...)
	return out
}

func incompleteStatus(status string) bool {
	switch strings.ToLower(status) {
	case "incomplete", "partial", "failed", "unsupported", "interrupted", "cancelled", "canceled":
		return true
	}
	return false
}

// ── Деградации ─────────────────────────────────────────────────────────────

// Подсистемы, у которых нет своего места в AnalysisResult (набор правил,
// модели, базы), сообщают о сбое через MarkDegraded. Реестр общий на процесс:
// скан один, а забыть о сбое, случившемся до старта пайплайна, нельзя.
var (
	degMu   sync.Mutex
	degSeen = map[string]struct{}{}
	degList []string
)

// MarkDegraded регистрирует деградацию компонента. Повторы игнорируются.
func MarkDegraded(component, reason string) {
	msg := component + ": " + reason
	degMu.Lock()
	defer degMu.Unlock()
	if _, ok := degSeen[msg]; ok {
		return
	}
	degSeen[msg] = struct{}{}
	degList = append(degList, msg)
}

// Degradations возвращает зарегистрированные деградации в порядке появления.
func Degradations() []string {
	degMu.Lock()
	defer degMu.Unlock()
	out := make([]string, len(degList))
	copy(out, degList)
	return out
}

// ResetDegradations очищает реестр (тесты и долгоживущие серверы между сканами).
func ResetDegradations() {
	degMu.Lock()
	defer degMu.Unlock()
	degSeen = map[string]struct{}{}
	degList = nil
}
