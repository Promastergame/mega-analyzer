package experts

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"decisionai/s1"
)

// ---------- Finding: verdicts of Mega-Analyzer's own scanners ----------

// Finding does NOT detect secrets or vulnerabilities. Mega-Analyzer already has a secrets scanner
// (pkg/internal/secrets: DetectProviders, VerifyStructure, Triage, the llmkeys junk judge) and a
// taint engine (binzap secretTaintSeeds: does the credential reach a log/network/file/IPC sink).
// This expert only turns their structured output into typed answers:
//
//	rule_id      "secret/stripe-key"            → category
//	severity     info|low|medium|high|critical  → severity score
//	confidence   0..1                           → scanner's own certainty
//	verified     structural check passed        (VerifyStructure.Verified)
//	placeholder  structure proves an example    (VerifyStructure.Placeholder)
//	expired      embedded expiry in the past    (VerifyStructure.Expired)
//	verdict      placeholder|expired-looking|real-looking|unclear (Triage.Verdict)
//	junk         llmkeys judge said "not a secret"
//	sink         log|network|file|ipc|none      (taint engine)
//	library      finding is inside third-party code
//
// Without scanner fields (only free text) it stays silent and the general model answers.
type Finding struct{}

func (Finding) Name() string { return "finding-rule" }

type scan struct {
	rule, kind, severity, verdict, sink string
	findingKind, assessment             string
	conf                                float64
	hasConf                             bool
	invalidConf, truncated              bool
	hasWitness, linkedSink, invalidFlow bool
	verified, placeholder, expired      bool
	junk, library                       bool
	hasLib                              bool
	ev                                  []string
	refs                                []s1.EvidenceReference
	next                                []s1.NextCheck
}

func readScan(state any) (scan, bool) {
	f := fields(state)
	s := scan{}
	str := func(names ...string) (string, string) {
		if p, v, ok := find(f, names...); ok {
			if x, ok := v.(string); ok {
				return p, strings.ToLower(strings.TrimSpace(x))
			}
		}
		return "", ""
	}
	flag := func(names ...string) (bool, bool) {
		if p, v, ok := find(f, names...); ok {
			if b, ok := v.(bool); ok {
				if b {
					s.ev = append(s.ev, show(p, v))
				}
				return b, true
			}
		}
		return false, false
	}
	var p string
	p, s.rule = str("rule_id", "ruleid", "rule")
	if s.rule != "" {
		s.ev = append(s.ev, show(p, s.rule))
	}
	p, s.verdict = str("verdict", "triage")
	if s.verdict != "" {
		s.ev = append(s.ev, show(p, s.verdict))
	}
	p, s.severity = str("severity")
	if s.severity != "" {
		s.ev = append(s.ev, show(p, s.severity))
	}
	if p, v, ok := find(f, "confidence", "scanner_confidence"); ok {
		switch x := v.(type) {
		case float64:
			s.conf, s.hasConf = x, true
		case string:
			if c, err := strconv.ParseFloat(x, 64); err == nil {
				s.conf, s.hasConf = c, true
			}
		}
		if s.hasConf {
			if math.IsNaN(s.conf) || math.IsInf(s.conf, 0) || s.conf < 0 || s.conf > 1 {
				s.hasConf, s.invalidConf = false, true
			} else {
				s.ev = append(s.ev, show(p, s.conf))
			}
		}
	}
	var ok1, ok2, ok3 bool
	s.verified, ok1 = flag("verified")
	s.placeholder, ok2 = flag("placeholder")
	s.expired, ok3 = flag("expired")
	s.junk, _ = flag("junk", "junk_value")
	if p, v, ok := find(f, "library", "is_library", "third_party"); ok {
		if b, ok := v.(bool); ok {
			s.library, s.hasLib = b, true
			s.ev = append(s.ev, show(p, v))
		}
	}
	p, s.sink = str("sink", "taint_sink", "reaches_sink")
	if s.sink != "" {
		s.ev = append(s.ev, show(p, s.sink))
	}
	p, s.findingKind = str("kind", "finding_kind")
	if s.findingKind != "" {
		s.ev = append(s.ev, show(p, s.findingKind))
	}
	p, s.assessment = str("explanation.status")
	if s.assessment != "" {
		s.ev = append(s.ev, show(p, s.assessment))
	}
	s.truncated, _ = flag("context_truncated")
	s.readSourceContext(state)
	// only scanner records count: a rule id or a triage/verification result must be present
	if s.rule == "" && s.verdict == "" && !ok1 && !ok2 && !ok3 {
		return scan{}, false
	}
	switch {
	case strings.HasPrefix(s.rule, "secret"), strings.Contains(s.rule, "credential"), strings.Contains(s.rule, "key"), strings.Contains(s.rule, "token"):
		s.kind = "secrets"
	case strings.Contains(s.rule, "crypt"), strings.Contains(s.rule, "hash"), strings.Contains(s.rule, "cipher"):
		s.kind = "crypto"
	case strings.Contains(s.rule, "cleartext"), strings.Contains(s.rule, "tls"), strings.Contains(s.rule, "ssl"), strings.Contains(s.rule, "network"):
		s.kind = "network"
	case strings.Contains(s.rule, "storage"), strings.Contains(s.rule, "prefs"), strings.Contains(s.rule, "file"):
		s.kind = "storage"
	}
	return s, true
}

func (s scan) realSink() bool {
	if s.sink == "" || s.sink == "none" || s.sink == "no" {
		return false
	}
	if s.findingKind != "" || s.assessment == "static_flow" {
		return s.linkedSink
	}
	return true // legacy records carry an explicit scanner verification result
}

// fpLogit: log-odds that the finding is a false positive, built only from scanner verdicts.
func (s scan) fpLogit() float64 {
	z := 0.0
	switch s.verdict {
	case "placeholder":
		z += 2.4
	case "expired-looking":
		z += 0.6 // a real but dead credential: rarely worth a fix, still not noise
	case "real-looking":
		z -= 1.4
	}
	if s.placeholder {
		z += 2.0
	}
	if s.expired { // structurally proven dead: nothing left to rotate
		z += 1.2
	}
	if s.junk {
		z += 1.5
	}
	if s.verified {
		z -= 1.6
	}
	if s.realSink() {
		z -= 1.2
	} else if s.sink == "none" {
		z += 0.6
	}
	// A bundled library can contain a real defect; its namespace is context,
	// not evidence that the finding is a false positive.
	if s.hasConf { // scanner certainty that this is a real hit
		c := math.Min(0.99, math.Max(0.01, s.conf))
		z -= 0.6 * math.Log(c/(1-c))
	}
	return z
}

var sevLevel = map[string]float64{"info": 0, "informational": 0, "low": 0.25, "medium": 0.5, "moderate": 0.5, "high": 0.75, "critical": 1}

// level in [0,1]: the scanner's severity, lowered when the verdicts say the value is not live.
func (s scan) level() (float64, bool) {
	l, ok := sevLevel[s.severity]
	if !ok {
		return 0, false
	}
	if s.placeholder || s.verdict == "placeholder" || s.junk {
		l = math.Min(l, 0.25)
	}
	if s.expired || s.verdict == "expired-looking" {
		l = math.Min(l, 0.25)
	}
	return l, true
}

var sevWords = []struct {
	l     float64
	words []string
}{
	{0, []string{"info", "информ"}},
	{0.25, []string{"low", "низк", "minor"}},
	{0.5, []string{"medium", "moderate", "средн"}},
	{0.75, []string{"high", "высок", "major", "серьёзн", "серьезн"}},
	{1, []string{"critical", "критич", "blocker"}},
}

func optionLevels(opts []s1.Option) []float64 {
	out := make([]float64, len(opts))
	for i, o := range opts {
		s := strings.ToLower(o.Key + " " + o.Text)
		out[i] = -1
		for _, lw := range sevWords {
			for _, w := range lw.words {
				if strings.Contains(s, w) {
					out[i] = lw.l
				}
			}
		}
	}
	for i := range out {
		if out[i] < 0 { // fall back to position on the scale
			out[i] = float64(i) / math.Max(1, float64(len(out)-1))
		}
	}
	return out
}

var kindWords = map[string][]string{
	"secrets": {"secret", "credential", "token", "key", "секрет", "ключ", "токен", "парол"},
	"crypto":  {"crypt", "cipher", "hash", "крипт", "шифр", "хэш", "хеш"},
	"network": {"network", "http", "tls", "ssl", "сет"},
	"storage": {"storage", "stor", "хранен", "файл"},
}

func kindOption(kind string, opts []s1.Option) int {
	for i, o := range opts {
		s := strings.ToLower(o.Key + " " + o.Text)
		for _, w := range kindWords[kind] {
			if strings.Contains(s, w) {
				return i
			}
		}
	}
	return -1
}

func (Finding) Answer(state any, _ string, q s1.ExpertQuestion) (answer s1.ExpertAnswer, handled bool) {
	if q.Task != "" && q.Task != s1.TaskFalsePositive && q.Task != s1.TaskSeverity {
		return s1.ExpertAnswer{}, false
	}
	var s scan
	defer func() {
		if handled {
			answer.References = append(evidenceReferences(answer.Evidence, state), s.refs...)
			if answer.Reason == "" {
				answer.Reason = "scanner_evidence"
			}
			if !answer.Calibrated {
				answer.Checks = s.contextChecks()
			}
		}
	}()
	id := strings.ToLower(q.ID + " " + q.Instr)
	has := func(ws ...string) bool {
		for _, w := range ws {
			if strings.Contains(id, w) {
				return true
			}
		}
		return false
	}
	var ok bool
	s, ok = readScan(state)
	if !ok {
		if q.Task != "" {
			return uncertain(q, "missing_scanner_evidence", "Нет структурного результата сканера."), true
		}
		return s1.ExpertAnswer{}, false
	}
	switch {
	case q.Type == s1.TypeNoul && (q.Task == s1.TaskFalsePositive || has("false_positive", "false positive", "ложн")):
		negative, known := noulMeaning(q, s1.TaskFalsePositive)
		if !known {
			return uncertain(q, "unsupported_question", "Уточните смысл вопроса или задайте task=false_positive."), true
		}
		if reason, detail := s.insufficientEvidence(); reason != "" {
			answer := uncertain(q, reason, detail)
			answer.Evidence = append(answer.Evidence, s.ev...)
			return answer, true
		}
		p := 1 / (1 + math.Exp(-s.fpLogit()))
		if negative {
			p = 1 - p
		}
		decisive := (s.verified && s.verdict == "real-looking" && s.realSink()) ||
			(s.placeholder && s.verdict == "placeholder")
		return s1.ExpertAnswer{Probs: []float64{p}, Evidence: s.ev, Calibrated: decisive}, true
	case q.Type == s1.TypeScore && len(q.Options) >= 2 && (q.Task == s1.TaskSeverity || has("severity", "серьёзн", "серьезн", "критичн", "risk", "риск")):
		if reason, detail := s.insufficientEvidence(); reason != "" {
			return uncertain(q, reason, detail), true
		}
		target, ok := s.level()
		if !ok {
			return s1.ExpertAnswer{}, false
		}
		lv := optionLevels(q.Options)
		probs := make([]float64, len(lv))
		for i, l := range lv {
			d := (l - target) * 4
			probs[i] = math.Exp(-d * d / 0.6)
		}
		ev := append([]string{fmt.Sprintf("серьёзность сканера %s, с учётом вердиктов %.2f по шкале 0..1", s.severity, target)}, s.ev...)
		return s1.ExpertAnswer{Probs: probs, Evidence: ev, Calibrated: s.verified || s.placeholder}, true
	case q.Type == s1.TypeChoice && s.kind != "" && has("categor", "категор", "kind", "тип"):
		k := kindOption(s.kind, q.Options)
		if k < 0 {
			return s1.ExpertAnswer{}, false
		}
		probs := make([]float64, len(q.Options))
		for i := range probs {
			probs[i] = 0.03 / math.Max(1, float64(len(probs)-1))
		}
		probs[k] = 0.97
		return s1.ExpertAnswer{Probs: probs, Evidence: append([]string{"категория по правилу сканера " + s.rule}, s.ev...), Calibrated: true}, true
	}
	return s1.ExpertAnswer{}, false
}
