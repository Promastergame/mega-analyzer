package decisionai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/finding"
)

type Entry struct {
	FindingID        string             `json:"finding_id"`
	Fingerprint      string             `json:"fingerprint"`
	RuleID           string             `json:"rule_id"`
	Title            string             `json:"title"`
	Severity         string             `json:"original_severity"`
	Locations        []finding.Location `json:"locations,omitempty"`
	StateSHA256      string             `json:"state_sha256"`
	ContextTruncated bool               `json:"context_truncated,omitempty"`
	AssessmentKind   string             `json:"assessment_kind"`
	ReviewRoute      string             `json:"review_route"`
	Response         Response           `json:"response"`
}

type Report struct {
	SchemaVersion int                 `json:"schema_version"`
	AdvisoryOnly  bool                `json:"advisory_only"`
	Status        string              `json:"status"`
	Total         int                 `json:"total_findings"`
	Selected      int                 `json:"selected_findings"`
	Reviewable    int                 `json:"reviewable_findings"`
	Observations  int                 `json:"observation_findings"`
	Processed     int                 `json:"processed_findings"`
	Skipped       int                 `json:"skipped_findings"`
	Error         string              `json:"error,omitempty"`
	InputSHA256   string              `json:"input_sha256"`
	Entries       []Entry             `json:"entries"`
	SourceReview  *SourceReviewReport `json:"source_review,omitempty"`
	CodeReview    *CodeReviewReport   `json:"code_review,omitempty"`
}

// Triage reads existing evidence only. It never changes a finding, severity,
// suppression decision, CI verdict or patch. Any service failure stops extra
// requests and remains visible in the report while the main scan can finish.
func Triage(ctx context.Context, client *Client, findings []finding.Finding, limit int) Report {
	return TriageWithPrior(ctx, client, findings, limit, nil)
}

// TriageWithPrior reuses advisory responses only when both the finding identity
// and the exact bounded request state still match. A report refresh can include
// new sidecar findings without querying unchanged evidence a second time.
func TriageWithPrior(ctx context.Context, client *Client, findings []finding.Finding, limit int, prior *Report) Report {
	r := Report{SchemaVersion: 1, AdvisoryOnly: true, Status: "complete", Total: len(findings), InputSHA256: FindingSnapshotSHA256(findings), Entries: []Entry{}}
	ordered := orderedFindings(findings)
	eligible := ordered[:0]
	for _, item := range ordered {
		if item.Kind == finding.KindInventory || item.Kind == finding.KindHardening {
			r.Observations++
			continue
		}
		eligible = append(eligible, item)
	}
	ordered = eligible
	r.Reviewable = len(ordered)
	if limit < 0 {
		limit = 0
	}
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	r.Selected = len(ordered)
	cached := make(map[string]Entry)
	if prior != nil && prior.AdvisoryOnly && prior.SchemaVersion == r.SchemaVersion {
		for _, entry := range prior.Entries {
			cached[entry.FindingID+"\x00"+entry.Fingerprint+"\x00"+entry.StateSHA256] = entry
		}
	}
	for _, f := range ordered {
		req, truncated := findingRequest(f)
		hash := sha256.Sum256(req.State)
		stateHash := hex.EncodeToString(hash[:])
		if previous, ok := cached[f.ID+"\x00"+f.Fingerprint+"\x00"+stateHash]; ok {
			r.Entries = append(r.Entries, previous)
			continue
		}
		if err := ctx.Err(); err != nil {
			r.Error = err.Error()
			break
		}
		response, err := client.Decide(ctx, req)
		if err != nil {
			r.Error = err.Error()
			break
		}
		answer := response.Answers["false_positive"]
		kind := "model_advisory"
		if answer.Source == "finding-rule" {
			kind = "scanner_rule_advisory"
		}
		route := "review"
		if answer.Abstained || answer.Route == "human" || truncated || len(answer.Evidence) == 0 || strings.Contains(strings.ToLower(response.Backend), "lexical") {
			route = "human"
		}
		r.Entries = append(r.Entries, Entry{
			FindingID: f.ID, Fingerprint: f.Fingerprint, RuleID: f.RuleID, Title: f.Title, Severity: f.Severity,
			Locations:   append([]finding.Location(nil), f.Locations...),
			StateSHA256: stateHash, ContextTruncated: truncated,
			AssessmentKind: kind, ReviewRoute: route, Response: response,
		})
	}
	r.Processed = len(r.Entries)
	r.Skipped = r.Total - r.Processed
	if r.Error != "" && r.Processed == 0 {
		r.Status = "unavailable"
	} else if r.Processed < r.Reviewable {
		r.Status = "partial"
	}
	return r
}

func orderedFindings(findings []finding.Finding) []finding.Finding {
	ordered := append([]finding.Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Fingerprint != b.Fingerprint {
			return a.Fingerprint < b.Fingerprint
		}
		return a.ID < b.ID
	})
	return ordered
}

// FindingSnapshotSHA256 ties an advisory report to all final finding identities
// and their request states, including findings skipped by the review budget.
func FindingSnapshotSHA256(findings []finding.Finding) string {
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	for _, f := range orderedFindings(findings) {
		req, _ := findingRequest(f)
		_ = encoder.Encode(struct {
			ID          string          `json:"id"`
			Fingerprint string          `json:"fingerprint"`
			State       json.RawMessage `json:"state"`
		}{f.ID, f.Fingerprint, req.State})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	default:
		return 0
	}
}

func findingRequest(f finding.Finding) (Request, bool) {
	truncated := false
	clip := func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		truncated = true
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		return s[:n]
	}
	// Keep the input bounded before marshalling, including unusual third-party
	// rule metadata. No files are opened from model-provided paths.
	state := map[string]any{
		"rule_id": clip(f.RuleID, 512), "kind": clip(string(f.Kind), 64),
		"category": clip(f.Category, 512), "title": clip(f.Title, 2048),
		"description": clip(f.Description, 4096), "severity": clip(f.Severity, 32),
	}
	if probability(f.Confidence) {
		state["confidence"] = f.Confidence
	}
	locations := make([]finding.Location, 0, min(len(f.Locations), 8))
	for i, loc := range f.Locations {
		if i == 8 {
			truncated = true
			break
		}
		loc.File, loc.Class, loc.Method = clip(loc.File, 1024), clip(loc.Class, 512), clip(loc.Method, 512)
		locations = append(locations, loc)
	}
	state["locations"] = locations
	evidence := make([]finding.Evidence, 0, min(len(f.Evidence), 8))
	for i, ev := range f.Evidence {
		if i == 8 {
			truncated = true
			break
		}
		ev.Type, ev.Description, ev.Snippet = clip(ev.Type, 128), clip(ev.Description, 1024), clip(ev.Snippet, 4096)
		ev.Digest = clip(ev.Digest, 128)
		ev.Location.File = clip(ev.Location.File, 1024)
		ev.Location.Class, ev.Location.Method = clip(ev.Location.Class, 512), clip(ev.Location.Method, 512)
		evidence = append(evidence, ev)
	}
	state["evidence"] = evidence
	// Supply the source context the scanner actually retained. A namespace is
	// a library hint, never a guarantee that packaged SDK code is unmodified.
	if hint, allLibrary := findingLibraryHint(f); hint != "" {
		state["library_hint"] = clip(hint, 1024)
		state["library_basis"] = "namespace hint; packaged code may be modified"
		if allLibrary {
			state["library"] = true
		}
	}
	steps := make([]finding.Step, 0, min(len(f.Steps), 16))
	for i, step := range f.Steps {
		if i == 16 {
			truncated = true
			break
		}
		step.File, step.Method, step.Type = clip(step.File, 1024), clip(step.Method, 1024), clip(step.Type, 128)
		steps = append(steps, step)
	}
	if len(steps) > 0 {
		state["steps"] = steps
	}
	if sink := findingStaticSink(f); sink != "" {
		state["sink"] = clip(sink, 1024)
		state["sink_basis"] = "retained static source-to-sink path; execution is not established"
	}
	if f.Explanation != nil {
		ex := *f.Explanation
		ex.Status, ex.Summary = clip(ex.Status, 64), clip(ex.Summary, 4096)
		boundList := func(values []string) []string {
			out := make([]string, 0, min(len(values), 16))
			for i, value := range values {
				if i == 16 {
					truncated = true
					break
				}
				out = append(out, clip(value, 1024))
			}
			return out
		}
		ex.Conditions, ex.Limitations, ex.NextChecks = boundList(ex.Conditions), boundList(ex.Limitations), boundList(ex.NextChecks)
		state["explanation"] = ex
	}
	state["context_truncated"] = truncated
	b, _ := json.Marshal(state) // only finite numbers and JSON-safe values above
	return Request{State: b, Questions: map[string]Question{
		"false_positive": {
			Type: "noul", Task: "false_positive", Polarity: "positive",
			Instructions: json.RawMessage(`"Does the supplied scanner evidence support treating this finding as a false positive? Missing runtime evidence is not proof of safety."`),
			Criteria:     json.RawMessage(`{"true":"The supplied evidence supports a false positive","false":"The supplied evidence supports a real finding"}`),
		},
	}}, truncated
}

// Text renders advisory results as plain text, safe to open in the existing
// web artifact browser. Model text is never treated as HTML or executable code.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "DecisionAI — дополнительный разбор находок\nСтатус: %s. Обработано рисков: %d/%d. Всего находок: %d. Без дополнительного разбора: %d.\nНаблюдения и защиты: %d (сохранены в основном отчёте).\n\n", r.Status, r.Processed, r.Reviewable, r.Total, r.Skipped, r.Observations)
	b.WriteString("Все ответы — рекомендации для проверки. Находки, severity и CI-вердикт не изменены.\nscanner_rule_advisory пересчитывает свидетельства сканера и не является независимым подтверждением.\nЧисло noul — оценка DecisionAI; её точность на ваших APK не измерена. При abstained число не является оценкой ложного срабатывания.\n\n")
	if r.Error != "" {
		fmt.Fprintf(&b, "Ошибка сервиса: %s\n\n", r.Error)
	}
	if r.SourceReview != nil {
		b.WriteString(r.SourceReview.Text())
	}
	if r.CodeReview != nil {
		b.WriteString(r.CodeReview.Text())
	}
	for _, entry := range r.Entries {
		a := entry.Response.Answers["false_positive"]
		fmt.Fprintf(&b, "%s | %s | %s\nID: %s\n", entry.RuleID, entry.Severity, entry.ReviewRoute, entry.FindingID)
		for _, loc := range entry.Locations {
			fmt.Fprintf(&b, "  %s:%d\n", loc.File, loc.Line)
		}
		fmt.Fprintf(&b, "Источник: %s (%s); версия %s; модель %s\n", a.Source, entry.AssessmentKind, entry.Response.Version, entry.Response.Model)
		if a.Abstained {
			b.WriteString("Оценка ложного срабатывания недоступна: разбор отказался от оценки.\n")
		} else if a.Noul != nil {
			fmt.Fprintf(&b, "Оценка ложного срабатывания: %.4f\n", *a.Noul)
		}
		if a.Abstained {
			fmt.Fprintf(&b, "Недостаточно данных: %s\n", a.Reason)
		}
		if entry.ContextTruncated {
			b.WriteString("Контекст сокращён до лимита; требуется ручная проверка.\n")
		}
		for _, ev := range a.Evidence {
			fmt.Fprintf(&b, "  Свидетельство: %s\n", ev)
		}
		for _, check := range a.Checks {
			fmt.Fprintf(&b, "  Проверить: %s — %s\n", check.Title, check.Why)
		}
		for _, warning := range entry.Response.Warnings {
			fmt.Fprintf(&b, "  Предупреждение: %s\n", warning)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
