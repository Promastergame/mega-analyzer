package experts

import (
	"fmt"
	"strings"
	"unicode"

	"decisionai/s1"
)

func normalizedQuestion(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == 'ё' || r == 'Ё' {
			return 'е'
		}
		if unicode.IsPunct(r) {
			return ' '
		}
		return unicode.ToLower(r)
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// Free-form questions are not commands for a deterministic expert. Only these
// unambiguous legacy forms are inferred; API clients use explicit task/polarity.
func noulMeaning(q s1.ExpertQuestion, task string) (negative, known bool) {
	if q.Task != "" {
		return q.Polarity == "negative", q.Task == task
	}
	s := normalizedQuestion(q.Instr)
	positive, inverse := []string{}, []string{}
	switch task {
	case s1.TaskPatchEffect:
		positive = []string{"подтвержден ли эффект патча", "подтвержден ли нужный эффект патча", "эффект патча подтвержден", "патч сработал", "патч работает", "was the patch effect confirmed", "is the patch effect confirmed", "did the patch work"}
		inverse = []string{"патч не сработал", "патч не работает", "эффект патча не подтвержден", "подтверждено ли отсутствие эффекта патча", "did the patch fail", "is the patch effect unconfirmed"}
	case s1.TaskFalsePositive:
		positive = []string{"это ложное срабатывание", "ложное срабатывание", "is this a false positive", "is the finding a false positive", "false positive"}
		inverse = []string{"это не ложное срабатывание", "это реальная проблема", "is this not a false positive", "is this a real finding"}
	case s1.TaskServerDependency:
		positive = []string{"поведение зависит от сервера", "зависит ли поведение от сервера", "есть ли зависимость от сервера", "does this depend on the server", "does the behavior depend on the server"}
		inverse = []string{"поведение не зависит от сервера", "поведение полностью локально", "is this fully local", "is this independent of the server"}
	}
	for _, text := range positive {
		if s == text {
			known = true
		}
	}
	for _, text := range inverse {
		if s == text {
			negative, known = true, true
		}
	}
	if !known {
		return false, false
	}
	// Conflicting criteria must not silently change a legacy question's meaning.
	for _, option := range q.Options {
		if option.Text == "" {
			continue
		}
		sign, ok := criterionMeaning(option.Text, task)
		if !ok {
			return false, false
		}
		wantNegative := negative
		if option.Key == "false" {
			wantNegative = !wantNegative
		}
		if sign != wantNegative {
			return false, false
		}
	}
	return negative, true
}

func criterionMeaning(text, task string) (negative, known bool) {
	s := normalizedQuestion(text)
	has := func(parts ...string) bool {
		for _, p := range parts {
			if strings.Contains(s, p) {
				return true
			}
		}
		return false
	}
	switch task {
	case s1.TaskPatchEffect:
		if has("не наблюдал", "не подтвержден", "отсутств", "не запускал", "не сработал", "not observed", "not confirmed", "no effect", "did not work") {
			return true, true
		}
		if has("наблюдал", "подтвержден", "сработал", "observed", "confirmed", "worked") {
			return false, true
		}
	case s1.TaskFalsePositive:
		if has("не реальная", "не секрет", "ложн", "заглуш", "тестовый", "мертвый", "placeholder", "false positive", "not real") {
			return false, true
		}
		if has("реальная", "живой", "реальный", "real problem", "real finding", "live secret") {
			return true, true
		}
	}
	return false, false
}

func uncertain(q s1.ExpertQuestion, reason, detail string) s1.ExpertAnswer {
	p := []float64{0.5}
	if q.Type != s1.TypeNoul {
		p = make([]float64, len(q.Options))
		for i := range p {
			p[i] = 1 / float64(len(p))
		}
	}
	return s1.ExpertAnswer{Probs: p, Abstained: true, Reason: reason, Evidence: []string{detail}}
}

func scopedText(state any, fallback string) string {
	if text, ok := state.(string); ok {
		return text
	}
	f := fields(state)
	var parts []string
	for _, name := range []string{"notes", "description", "observation"} {
		if _, value, ok := find(f, name); ok {
			if text, ok := value.(string); ok {
				parts = append(parts, text)
			}
		}
	}
	return strings.Join(parts, "\n")
}

func patchChecks(f map[string]any) []s1.NextCheck {
	var checks []s1.NextCheck
	for _, item := range []struct {
		names                []string
		id, title, why, kind string
	}{
		{[]string{"build.status", "build_status", "build"}, "build_current", "Собрать текущий кандидат", "Сборка должна завершиться успешно для проверяемой версии.", "build"},
		{[]string{"sha256_matches", "hash_matches", "sha_matches", "build.sha256_matches"}, "match_candidate", "Сверить SHA-256 сборки и кандидата", "Результат другой версии не подтверждает текущий патч.", "identity"},
		{[]string{"runtime.status", "runtime_status", "runtime", "test.status", "tests.status"}, "run_current", "Выполнить сценарий на текущей сборке", "Нужен завершённый тест поведения.", "runtime"},
		{[]string{"effect_verified", "effect_confirmed", "effect_observed"}, "compare_before_after", "Сравнить результат до и после", "Зафиксировать ожидаемое изменение и побочные эффекты.", "comparison"},
	} {
		if _, v, ok := find(f, item.names...); !ok || statusOf(v) != pass {
			checks = append(checks, s1.NextCheck{ID: item.id, Title: item.title, Why: item.why, Kind: item.kind})
		}
	}
	return checks
}

func evidenceReferences(evidence []string, state any) []s1.EvidenceReference {
	f := fields(state)
	var refs []s1.EvidenceReference
	for _, text := range evidence {
		path, _, ok := strings.Cut(text, ":")
		if !ok {
			continue
		}
		if _, exists := f[path]; exists {
			refs = append(refs, s1.EvidenceReference{Kind: "field", Path: path})
		}
	}
	if _, file, ok := find(f, "file", "path"); ok {
		ref := s1.EvidenceReference{Kind: "source", File: fmt.Sprint(file)}
		if _, line, ok := find(f, "line"); ok {
			if n, ok := line.(float64); ok && n > 0 {
				ref.Line = int(n)
			}
		}
		refs = append(refs, ref)
	}
	return refs
}
