package experts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"decisionai/s1"
)

// SourceEvidence validates the citation contract of a typed static scanner
// check. It does not re-run data-flow analysis, infer runtime execution,
// promote scanner checks to independent evidence or answer from keywords.
type SourceEvidence struct{}

func (SourceEvidence) Name() string { return "source-evidence-rule" }

type sourceCitation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Method  string `json:"method"`
	Snippet string `json:"snippet"`
	SHA256  string `json:"sha256"`
}
type checkedSource struct {
	File           string `json:"file"`
	Line           int    `json:"line"`
	Method         string `json:"method"`
	Representation string `json:"representation"`
	SHA256         string `json:"sha256"`
	Code           string `json:"code"`
}
type sourceRecord struct {
	SchemaVersion int  `json:"schema_version"`
	StaticOnly    bool `json:"static_only"`
	Check         struct {
		ID        string           `json:"id"`
		Kind      string           `json:"kind"`
		Status    string           `json:"status"`
		Choice    string           `json:"choice"`
		Basis     string           `json:"basis"`
		Scope     string           `json:"scope"`
		Summary   string           `json:"summary"`
		Reason    string           `json:"reason"`
		Method    string           `json:"method"`
		Sink      string           `json:"sink"`
		Citations []sourceCitation `json:"citations"`
	} `json:"check"`
	Sources []checkedSource `json:"sources"`
}

func (SourceEvidence) Answer(state any, _ string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if q.Task != s1.TaskSourceEvidence {
		return s1.ExpertAnswer{}, false
	}
	fail := func(reason string) (s1.ExpertAnswer, bool) {
		answer := uncertain(q, reason, "Полный, непротиворечивый контракт статических источников не подтверждён.")
		// Keep the declared escape option, even if a caller reorders criteria.
		for i, option := range q.Options {
			if option.Key == "unresolved" {
				answer.Probs = make([]float64, len(q.Options))
				answer.Probs[i] = 1
				break
			}
		}
		answer.Checks = []s1.NextCheck{{ID: "complete_source_check", Title: "Проверить полный исходный контекст", Why: "Нужны полные методы, вызывающий код и согласованные ссылки; выполнение не установлено.", Kind: "source"}}
		return answer, true
	}
	obj := findingObject(state)
	raw, err := json.Marshal(obj["source_evidence"])
	if err != nil || string(raw) == "null" {
		return fail("missing_source_contract")
	}
	var record sourceRecord
	if json.Unmarshal(raw, &record) != nil || record.SchemaVersion != 1 || !record.StaticOnly {
		return fail("invalid_source_contract")
	}
	check := record.Check
	if q.Type != s1.TypeChoice || !allowedSourceChoice(check.Kind, check.Choice) {
		return fail("unsupported_source_check")
	}
	basis, scope := "cfg_reaching_definitions", "retained_call_sites"
	if check.Kind == "manifest_cleartext" || check.Kind == "component_surface" {
		basis, scope = "xml_declaration", "declaration_only"
		if check.Status == "unresolved" {
			scope = "retained_manifest"
		}
	}
	if check.ID == "" || check.Basis != basis || check.Scope != scope {
		return fail("invalid_source_provenance")
	}
	if check.Status == "unresolved" || check.Choice == "unresolved" {
		reason := check.Reason
		if reason == "" {
			reason = "unresolved_source_check"
		}
		return fail(reason)
	}
	if check.Status != "supported" && check.Status != "observed" && check.Status != "unreachable" {
		return fail("invalid_source_status")
	}
	if len(check.Citations) == 0 || len(check.Citations) > 32 || len(record.Sources) == 0 || len(record.Sources) > 128 {
		return fail("missing_source_citations")
	}
	var references []s1.EvidenceReference
	for _, c := range check.Citations {
		valid := false
		for _, source := range record.Sources {
			if source.File != c.File || source.Method != c.Method || source.SHA256 != c.SHA256 || source.Line < 1 ||
				c.Line < source.Line || c.Snippet == "" || len(source.Code) > 192<<10 {
				continue
			}
			switch source.Representation {
			case "retained_smali_method", "retained_decoded_manifest":
			default:
				continue
			}
			sum := sha256.Sum256([]byte(source.Code))
			if hex.EncodeToString(sum[:]) != source.SHA256 {
				continue
			}
			lines := strings.Split(source.Code, "\n")
			row := c.Line - source.Line
			if row >= len(lines) {
				continue
			}
			// A manifest start tag may span lines; it must begin at its cited
			// line. Smali citations are the complete retained instruction.
			lineTail := strings.TrimSpace(strings.Join(lines[row:], "\n"))
			if source.Representation == "retained_smali_method" {
				valid = strings.TrimSpace(lines[row]) == c.Snippet
			} else {
				valid = strings.HasPrefix(lineTail, c.Snippet)
			}
			if valid {
				break
			}
		}
		if !valid {
			return fail("source_digest_or_location_mismatch")
		}
		references = append(references, s1.EvidenceReference{Kind: "source", File: c.File, Line: c.Line, SHA256: c.SHA256})
	}
	selected := -1
	for i, option := range q.Options {
		if option.Key == check.Choice {
			selected = i
			break
		}
	}
	if selected < 0 {
		return fail("missing_source_choice")
	}
	probs := make([]float64, len(q.Options))
	probs[selected] = 1
	return s1.ExpertAnswer{Probs: probs, References: references,
		Evidence: []string{fmt.Sprintf("Статическая проверка сканера (%s): %s", check.Basis, check.Summary),
			"Ссылки и SHA-256 согласуются с сохранёнными источниками. Анализ потока выполнен сканером; выполнение, эксплуатация и независимое подтверждение не установлены."},
		Checks:     []s1.NextCheck{{ID: "source_conditions", Title: "Проверить условия использования", Why: "Сохранённый код не устанавливает истинность условий ветвей, содержимое скрытого кода или наблюдаемое выполнение.", Kind: "source"}},
		Calibrated: false}, true
}

func allowedSourceChoice(kind, choice string) bool {
	if choice == "unresolved" {
		switch kind {
		case "native_load", "path_origin", "output_name", "manifest_cleartext", "component_surface":
			return true
		}
	}
	switch kind {
	case "native_load":
		return choice == "static_call_path" || choice == "unreachable_call"
	case "path_origin":
		return choice == "application_data_dir" || choice == "archive_entry_name" || choice == "constant_path" || choice == "unbound_parameter"
	case "output_name":
		return choice == "constant_filename" || choice == "archive_entry_name"
	case "manifest_cleartext":
		return choice == "explicit_true" || choice == "explicit_false" || choice == "not_declared"
	case "component_surface":
		return choice == "declared_component"
	}
	return false
}
