// Package sourceevidence describes bounded, cited static source checks.
// These checks describe the retained code, not execution or exploitability.
package sourceevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	SchemaVersion  = 1
	MaxChecks      = 128
	MaxCitations   = 32
	MaxSources     = 128
	MaxSourceBytes = 192 << 10
)

type Citation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Method  string `json:"method,omitempty"`
	Snippet string `json:"snippet"`
	SHA256  string `json:"sha256"`
}

// Source binds a citation to the exact retained representation. DEX-emitted
// Smali and decoded AXML are explicitly identified; their digest is not the
// digest of the original APK or binary manifest.
type Source struct {
	File           string `json:"file"`
	Line           int    `json:"line"`
	Method         string `json:"method,omitempty"`
	Representation string `json:"representation"`
	SHA256         string `json:"sha256"`
	Code           string `json:"code"`
}

type Check struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Status    string     `json:"status"` // supported, observed, unresolved, unreachable
	Choice    string     `json:"choice"`
	Basis     string     `json:"basis"`
	Scope     string     `json:"scope"`
	Summary   string     `json:"summary"`
	Reason    string     `json:"reason,omitempty"`
	Method    string     `json:"method,omitempty"`
	Sink      string     `json:"sink,omitempty"`
	Citations []Citation `json:"citations"`
}

type Report struct {
	SchemaVersion     int      `json:"schema_version"`
	StaticOnly        bool     `json:"static_only"`
	Status            string   `json:"status"`
	MethodsDiscovered int      `json:"methods_discovered"`
	MethodsAnalyzed   int      `json:"methods_analyzed"`
	MethodsSkipped    int      `json:"methods_skipped"`
	ChecksConsidered  int      `json:"checks_considered"`
	ChecksOmitted     int      `json:"checks_omitted"`
	SliceSteps        int      `json:"slice_steps"`
	LimitReached      bool     `json:"limit_reached"`
	Cancelled         bool     `json:"cancelled"`
	Checks            []Check  `json:"checks"`
	Sources           []Source `json:"sources"`
}

func NewReport() Report {
	return Report{SchemaVersion: SchemaVersion, StaticOnly: true, Status: "complete", Checks: []Check{}, Sources: []Source{}}
}

func Digest(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func CheckID(kind, method, file string, line int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", kind, method, file, line)))
	return kind + "_" + hex.EncodeToString(sum[:8])
}

// AddSource keeps source snapshots whole: dropping an oversized method is
// safer than manufacturing a source proof from a truncated method body.
func (r *Report) AddSource(source Source) bool {
	for _, existing := range r.Sources {
		if existing.File == source.File && existing.Line == source.Line && existing.SHA256 == source.SHA256 {
			return true
		}
	}
	total := len(source.Code)
	for _, existing := range r.Sources {
		total += len(existing.Code)
	}
	if len(r.Sources) >= MaxSources || total > MaxSourceBytes {
		r.LimitReached, r.Status = true, "partial"
		return false
	}
	r.Sources = append(r.Sources, source)
	return true
}

func (r *Report) AddCheck(check Check) {
	r.ChecksConsidered++
	if len(r.Checks) >= MaxChecks {
		r.ChecksOmitted++
		r.LimitReached, r.Status = true, "partial"
		return
	}
	if len(check.Citations) > MaxCitations {
		check.Citations = check.Citations[:MaxCitations]
		check.Status, check.Choice, check.Reason = "unresolved", "unresolved", "citation_limit"
		r.LimitReached, r.Status = true, "partial"
	}
	r.Checks = append(r.Checks, check)
}

func (r Report) SHA256() string {
	// Maps are absent and the producer orders slices deterministically.
	data, _ := json.Marshal(r)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Проверка исходного кода: %s\nМетоды: %d/%d; пропущено: %d. Проверки: %d; не сохранено: %d.\n\n",
		r.Status, r.MethodsAnalyzed, r.MethodsDiscovered, r.MethodsSkipped, len(r.Checks), r.ChecksOmitted)
	b.WriteString("Статические свидетельства из сохранённого кода. Выполнение, достижимость во время работы и эксплуатация не установлены.\nИсточники и их SHA-256 относятся к указанному представлению кода.\n\n")
	for _, check := range r.Checks {
		fmt.Fprintf(&b, "%s | %s | %s\n%s\n", check.Kind, check.Status, check.Choice, check.Summary)
		if check.Reason != "" {
			fmt.Fprintf(&b, "Ограничение: %s\n", check.Reason)
		}
		for _, c := range check.Citations {
			fmt.Fprintf(&b, "  %s:%d  %s\n", c.File, c.Line, c.Snippet)
		}
		b.WriteString("\n")
	}
	return b.String()
}
