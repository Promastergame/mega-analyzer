package experts

import (
	"fmt"
	"math"
	"strings"

	"decisionai/s1"
)

func findingObject(state any) map[string]any {
	obj, _ := state.(map[string]any)
	if current, exists := obj["current"]; exists {
		obj, _ = current.(map[string]any)
	}
	return obj
}

func contextString(obj map[string]any, name string) string {
	value, _ := obj[name].(string)
	return strings.TrimSpace(value)
}

func shortContext(text string) string {
	runes := []rune(text)
	if len(runes) > 512 {
		return string(runes[:512]) + "…"
	}
	return text
}

func (s *scan) readSourceContext(state any) {
	obj := findingObject(state)
	if obj == nil {
		return
	}
	if evidence, ok := obj["evidence"].([]any); ok {
		for i, value := range evidence {
			if i >= 8 {
				break
			}
			record, _ := value.(map[string]any)
			location, _ := record["location"].(map[string]any)
			file, snippet := contextString(location, "file"), contextString(record, "snippet")
			if file == "" || snippet == "" {
				continue
			}
			s.hasWitness = true
			s.ev = append(s.ev, fmt.Sprintf("evidence[%d].snippet: %s", i, shortContext(snippet)))
			ref := s1.EvidenceReference{Kind: "source", File: shortContext(file), SHA256: contextString(record, "digest")}
			if line, ok := location["line"].(float64); ok && line > 0 && line <= math.MaxInt32 && line == math.Trunc(line) {
				ref.Line = int(line)
			}
			s.refs = append(s.refs, ref)
		}
	}
	// Static-flow evidence must retain an ordered source and sink, including
	// their source locations. A field named sink alone does not supply a path.
	if steps, ok := obj["steps"].([]any); ok {
		hasSource := false
		for i, value := range steps {
			if i >= 16 {
				break
			}
			step, _ := value.(map[string]any)
			if contextString(step, "method") == "" || contextString(step, "file") == "" {
				continue
			}
			switch contextString(step, "type") {
			case "source":
				hasSource = true
			case "sink":
				if hasSource && strings.ToLower(contextString(step, "method")) == s.sink && s.assessment == "static_flow" {
					s.linkedSink, s.hasWitness = true, true
				}
			}
		}
	}
	s.invalidFlow = s.assessment == "static_flow" && !s.linkedSink
	explanation, _ := obj["explanation"].(map[string]any)
	if checks, ok := explanation["next_checks"].([]any); ok {
		for i, value := range checks {
			if i >= 3 {
				break
			}
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				s.next = append(s.next, s1.NextCheck{ID: fmt.Sprintf("scanner_next_%d", i+1), Title: shortContext(text), Why: "Оставшаяся проверка из исходного результата сканера.", Kind: "source"})
			}
		}
	}
}

func (s scan) insufficientEvidence() (string, string) {
	switch {
	case s.invalidConf:
		return "invalid_scanner_confidence", "Уверенность сканера должна быть конечным числом в диапазоне 0..1."
	case s.truncated:
		return "truncated_scanner_context", "Контекст сокращён; полный результат нужно проверить перед оценкой ложного срабатывания."
	case (s.placeholder || s.junk || s.verdict == "placeholder") && (s.verified || s.verdict == "real-looking"):
		return "contradictory_scanner_evidence", "Структурные признаки реальной находки и заглушки противоречат друг другу."
	case s.findingKind == "inventory" || s.findingKind == "hardening" || s.assessment == "observation":
		return "observation_not_defect", "Наблюдение API или защиты не является утверждением о дефекте либо вредоносном поведении."
	case s.invalidFlow:
		return "incomplete_static_path", "Для static_flow не сохранён полный путь от источника к заявленному приёмнику."
	case s.assessment == "needs_review":
		return "unresolved_scanner_conditions", "Детектор оставил существенные условия непроверенными; высокая уверенность в совпадении не разрешает их."
	}
	explicitVerdict := s.verified || s.placeholder || s.junk || s.expired || s.verdict == "placeholder" || s.verdict == "real-looking" || s.verdict == "expired-looking"
	if !explicitVerdict && !s.hasWitness {
		return "missing_source_evidence", "Название правила, severity, уверенность и принадлежность библиотеке не заменяют исходные свидетельства."
	}
	if !explicitVerdict && !s.realSink() && (s.assessment == "heuristic" || s.findingKind == "malware") {
		return "unlinked_behavior_evidence", "Совместное наличие возможностей не устанавливает связанное поведение или семейство вредоносной программы."
	}
	return "", ""
}

func (s scan) contextChecks() []s1.NextCheck {
	checks := append([]s1.NextCheck(nil), s.next...)
	if s.truncated {
		checks = append(checks, s1.NextCheck{ID: "full_source_context", Title: "Открыть полный контекст находки", Why: "Сокращённый запрос не содержит всех исходных свидетельств.", Kind: "source"})
	} else if len(checks) == 0 {
		checks = append(checks, s1.NextCheck{ID: "verify_context", Title: "Проверить путь и условия использования", Why: "Проверить достижимость, источник данных, проверки входа и фактический приёмник; статический результат не устанавливает выполнение.", Kind: "source"})
	}
	if s.library {
		checks = append(checks, s1.NextCheck{ID: "verify_library_context", Title: "Проверить код и версию библиотеки", Why: "Имя пространства имён не подтверждает неизменность SDK и не исключает уязвимость.", Kind: "source"})
	}
	return checks
}
