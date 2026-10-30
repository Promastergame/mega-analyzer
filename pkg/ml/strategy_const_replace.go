package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONST REPLACE STRATEGY — обобщенная замена строковых констант
//
// SmartPatcher умеет только URL-редирект (const_replace с OriginalURL).
// Но серверные ключи, feature-флаги, endpoint-пути, подписи — тоже const-string,
// и их замена — самый безопасный патч вообще: const-string фиксирован (21c,
// 2u), payload в string pool → замена литерала НЕ сдвигает layout.
//
// Стратегия параметризуется парой (target → replacement):
//   - CanApply: в теле есть const-string, содержащий target-подстроку
//     (из сигналов или эвристики: URL, ключи, пути).
//   - Generate: ReplaceAll target→replacement внутри тела (offset-safe).
//
// Два режима:
//   1. Explicit: mi.SecurityStrings содержит target (анализатор подсветил).
//   2. Heuristic: URL/endpoint в const-string (как SmartPatcher, но как
//      стратегия селектора, а не отдельный тракт).
//
// Приоритет 85 — ниже surgical-чисел (86-90, семантика сильнее), выше
// стабов (80): замена строки сохраняет ВСЕ, включая CFG.
// ═══════════════════════════════════════════════════════════════════════════════

// ConstReplaceStrategy заменяет строковые константы.
type ConstReplaceStrategy struct {
	priority    int
	target      string // что ищем (пусто = эвристика по URL)
	replacement string // на что меняем
}

// NewConstReplaceStrategy создаёт стратегию с эвристикой URL.
func NewConstReplaceStrategy() *ConstReplaceStrategy {
	return &ConstReplaceStrategy{priority: 85}
}

// NewConstReplaceStrategyWith создаёт стратегию с явной парой.
func NewConstReplaceStrategyWith(target, replacement string) *ConstReplaceStrategy {
	return &ConstReplaceStrategy{priority: 85, target: target, replacement: replacement}
}

// lifecycleCallbackNames — точные имена Android/UI колбэков. Замена литералов
// в onCreate/onResume/... никогда не обходит проверку: это шум (как blank
// строки ошибок в MainActivity.onCreate), а не байпасс.
var lifecycleCallbackNames = []string{
	"oncreate", "onstart", "onstop", "onresume", "onpause", "ondestroy",
	"onactivityresult", "onfragmentresult", "onattach", "ondetach",
	"onmeasure", "onlayout", "ondraw", "onbackpressed", "ondismiss",
	"oncancel", "onshow", "onsaveinstancestate", "onrestoreinstancestate",
	"oncontentchanged", "onwindowfocuschanged", "ontrimemory", "onlowmemory",
	"onconfigurationchanged",
}

// isLifecycleCallbackName reports exact-match lifecycle callbacks.
func isLifecycleCallbackName(nameLower string) bool {
	for _, lc := range lifecycleCallbackNames {
		if nameLower == lc {
			return true
		}
	}
	return false
}

// CanApply: есть const-string с таргетом.
func (s *ConstReplaceStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	name := mi.NameLower
	if name == "" {
		name = strings.ToLower(mi.Name)
	}
	// Explicit target pairs bypass this: the caller takes responsibility.
	// The URL/security-string heuristic must not fire inside lifecycle
	// callbacks, where literal swaps are noise rather than bypasses.
	if s.target == "" && isLifecycleCallbackName(name) {
		return false
	}
	if len(mi.RawBody) == 0 {
		return false
	}
	targets := s.targetsFor(mi)
	if len(targets) == 0 {
		return false
	}
	body := strings.Join(mi.RawBody, "\n")
	for _, t := range targets {
		if t != "" && strings.Contains(body, t) {
			// Проверяем что таргет именно в const-string, а не в комментарии
			for _, line := range mi.RawBody {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "const-string") && strings.Contains(line, t) {
					return true
				}
			}
		}
	}
	return false
}

// Generate заменяет константы.
func (s *ConstReplaceStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	targets := s.targetsFor(mi)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no replace targets")
	}
	repl := s.replacement
	if repl == "" {
		repl = "http://127.0.0.1:5555/"
	}
	out := make([]string, len(mi.RawBody))
	copy(out, mi.RawBody)
	count := 0
	for i, line := range out {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "const-string") {
			continue
		}
		for _, t := range targets {
			if t != "" && strings.Contains(line, t) {
				r := repl
				// Для не-URL таргетов (ключи/флаги) пустая строка безопаснее,
				// чем localhost. URL → localhost, остальное → "".
				if !isURLLike(t) {
					r = ""
				}
				out[i] = strings.ReplaceAll(line, t, r)
				count++
				break
			}
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("no const-string occurrences replaced")
	}
	smaliCode := strings.Join(out, "\n")
	// Self-validation (как у NopInjection): const-replace обязана быть
	// offset-safe, но вход мог быть СЛОМАН заранее (v4 при .registers 2).
	// Невалидный smali не шиппим — возвращаем ошибку, вызыватель уйдет
	// в fallback-цепочку (GenerateBest) или legacy-стаб.
	if !NewSmaliValidator().ValidateStrict(smaliCode).Valid {
		// Если и оригинал был невалиден — это не наша вина, но и не наш патч.
		return nil, fmt.Errorf("const-replace output failed strict validation")
	}
	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchConstReplace,
		Description:  fmt.Sprintf("Replace %d const-string occurrence(s) (offset-safe, string-pool only)", count),
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason:       fmt.Sprintf("Method %s embeds server-controlled literals.", mi.Name),
			WhatItDoes:   "Rewrites only the string-pool payload; code units never shift.",
			WhyThisPatch: "Const-string replace is the least invasive patch class: no CFG/DFG impact, no register pressure.",
			Impact:       "Network/flag lookups point at the test fixture instead of production.",
			Signals:      []string{fmt.Sprintf("Const targets: %v", targets)},
		},
	}
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *ConstReplaceStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *ConstReplaceStrategy) PatchType() PatchType { return PatchConstReplace }

// GetDescription returns a human-readable description.
func (s *ConstReplaceStrategy) GetDescription() string {
	return "Offset-safe const-string replacement (URL/key/flag → fixture): string-pool only, zero layout shift."
}

func (s *ConstReplaceStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "const_replace",
		SupportedRoles:       []MethodRole{MethodRoleBooleanGate, MethodRoleWrapper, MethodRoleValueProvider},
		PreservesControlFlow: true,
	}
}

// targetsFor возвращает список таргетов: явный > security-строки > URL-эвристика.
//
// ВАЖНО: summarizeMethodBodyForStrategy кладет в SecurityStrings ЦЕЛЫЕ СТРОКИ
// вида `const-string v4, "Emulator"`, а не чистый литерал. Подставлять такую
// строку в ReplaceAll целиком — значит стереть всю инструкцию в пустую строку
// (было: `const-string v4, "Emulator"` → `    `). Поэтому здесь извлекаем
// только payload между кавычками.
func (s *ConstReplaceStrategy) targetsFor(mi *shared.MethodInfo) []string {
	if s.target != "" {
		if lit := extractStringLiteral(s.target); lit != "" {
			return []string{lit}
		}
		return []string{s.target}
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(t string) {
		if t == "" || len(t) < 2 || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, str := range mi.SecurityStrings {
		if lit := extractStringLiteral(str); lit != "" {
			add(lit)
		} else if len(str) >= 4 && !strings.Contains(str, " ") {
			add(str)
		}
	}
	for _, str := range mi.StringConsts {
		if lit := extractStringLiteral(str); lit != "" {
			if isURLLike(lit) {
				add(lit)
			}
		} else if isURLLike(str) {
			add(str)
		}
	}
	return out
}

// extractStringLiteral вытаскивает payload между первыми кавычками:
// `const-string v4, "Emulator"` → `Emulator`. Пусто если кавычек нет.
func extractStringLiteral(s string) string {
	first := strings.Index(s, "\"")
	if first < 0 {
		return ""
	}
	rest := s[first+1:]
	// Ищем закрывающую НЕэкранированную кавычку.
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' {
			i++ // пропускаем экранированный символ
			continue
		}
		if rest[i] == '"' {
			return rest[:i]
		}
	}
	return rest // незакрытая кавычка — берем остаток
}

func isURLLike(str string) bool {
	l := strings.ToLower(str)
	return strings.Contains(l, "http://") || strings.Contains(l, "https://") ||
		strings.Contains(l, "127.0.0.1") || strings.Contains(l, "example.test") ||
		strings.Contains(l, "/economy/") || strings.Contains(l, "/subscription/") ||
		strings.Contains(l, "/age/") || strings.Contains(l, "/features")
}
