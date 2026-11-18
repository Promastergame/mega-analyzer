// Package smalirole answers one typed question about Smali code, Jev-style:
// "what role does this literal play?" -> one label from a fixed schema, a probability for every label,
// the traced evidence, and a generated explanation grounded in that evidence.
//
// Pipeline: parse -> CFG -> def-use trace (aliases, one level into app callees) -> signals ->
// learned logistic model (temperature-calibrated) + expert rule votes -> softmax -> abstain gate -> text.
package smalirole

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const Version = "0.5.0"

type Request struct {
	Code      string   `json:"code"`
	Line      int      `json:"line"`
	Threshold *float64 `json:"threshold,omitempty"`
	Class     string   `json:"class,omitempty"` // optional Lcom/foo/Bar; of the method
}

type Evidence struct {
	Line   int      `json:"line"`
	Text   string   `json:"text"`
	Signal string   `json:"signal"`
	Via    string   `json:"via,omitempty"`
	Tags   []string `json:"tags"`
}

type Prob struct {
	Label string  `json:"label"`
	P     float64 `json:"probability"`
}

type Report struct {
	Version     string     `json:"version"`
	ConstLine   int        `json:"const_line"`
	Register    string     `json:"register"`
	Literal     string     `json:"literal"`
	Int32       int64      `json:"int32"`
	Uint32      uint64     `json:"uint32"`
	Answer      string     `json:"answer"`
	Confidence  float64    `json:"confidence"`
	Threshold   float64    `json:"threshold"`
	Abstained   bool       `json:"abstained"`
	Probs       []Prob     `json:"distribution"`
	Evidence    []Evidence `json:"evidence"`
	Explanation string     `json:"explanation"`
	Scorer      string     `json:"scorer"`
	FloatValue  *float64   `json:"float_value,omitempty"`
	Wide        bool       `json:"wide,omitempty"`
	TimeUnit    bool       `json:"time_unit_arg,omitempty"` // duration unit comes from a TimeUnit argument
	Stored      []string   `json:"stored_fields,omitempty"` // fields the literal is written to in this method
}

var signalRU = map[string]string{
	"op:and": "побитовое AND", "op:or": "побитовое OR", "op:xor": "побитовое XOR", "op:shifted": "сдвигается",
	"op:shift_amount": "величина сдвига", "op:addsub": "сложение/вычитание", "op:muldiv": "умножение/деление",
	"op:convert": "преобразование типа", "cmp:order": "сравнение «больше/меньше»", "cmp:eq": "сравнение на равенство",
	"cmp:zero_self": "проверка на ноль/знак", "ret": "возвращается из метода", "newarray": "размер массива",
	"aindex": "индекс массива", "astore": "кладётся в массив", "switch": "значение switch",
}

func describe(tags []string) string {
	var parts []string
	for _, t := range tags {
		t = strings.TrimPrefix(t, "callee:")
		switch {
		case signalRU[t] != "":
			parts = append(parts, signalRU[t])
		case strings.HasPrefix(t, "call:") && !strings.Contains(t, "tok:") && t != "call:platform":
			parts = append(parts, "аргумент "+t[5:]+"()")
		case strings.HasPrefix(t, "arg:type:"):
			parts = append(parts, "параметр типа "+t[9:])
		case strings.HasPrefix(t, "field:type:"):
			parts = append(parts, "пишется в поле типа "+t[11:])
		case strings.HasPrefix(t, "cmpwith:result"):
			parts = append(parts, "с результатом вызова")
		case t == "cmpwith:field":
			parts = append(parts, "с полем")
		case t == "cmpwith:length":
			parts = append(parts, "с длиной массива")
		}
	}
	if len(parts) == 0 {
		return "использование"
	}
	return strings.Join(parts, ", ")
}

// ExpertLogits converts rule votes for all use signals into logits.
func ExpertLogits(sigs [][]string) []float64 {
	z := make([]float64, len(Labels))
	for _, sg := range sigs {
		for _, s := range sg {
			for l, w := range expertVotes[strings.TrimPrefix(s, "callee:")] {
				if strings.HasPrefix(s, "callee:") {
					w *= 0.6
				}
				z[labelIndex(l)] += w
			}
		}
	}
	return z
}

func literalPrior(s *Site) []float64 {
	z := make([]float64, len(Labels))
	add := func(l string, w float64) { z[labelIndex(l)] += w }
	hex := strings.Contains(strings.ToLower(s.Literal), "0x")
	switch v, u := s.V, s.U; {
	case u>>24 == 0x7f && u&0x00ff0000 != 0:
		add("resource_id", 3)
	case v == -1:
		add("sentinel", 1)
		add("bitmask", .6)
		add("layout_param", .3)
		if hex {
			add("color_argb", .6)
			add("bitmask", .4)
		}
	case v == -2:
		add("layout_param", 1)
	case v == math.MaxInt32:
		add("limit_threshold", 1)
		add("bitmask", .6)
	case u>>24 >= 0x80 && hex:
		add("color_argb", 1)
		add("bitmask", .5)
	case (v == 0 || v == 1) && s.Method.Ret == "Z":
		add("boolean", 2)
	case v > 1 && v&(v-1) == 0:
		add("flag_bit", .8)
		add("bitmask", .3)
	case v >= 100 && v%100 == 0:
		add("duration_ms", .5)
		add("limit_threshold", .5)
	}
	return z
}

// Score combines the learned model (if any) with expert votes.
func Score(s *Site, model *Model) ([]float64, string) {
	ex := ExpertLogits(s.Sigs)
	if model == nil {
		z := literalPrior(s)
		for k := range z {
			z[k] += 1.3*ex[k] - 1
		}
		z[labelIndex("unknown")] = 0.5
		return Softmax(z, 1), "expert-rules-v0 (uncalibrated)"
	}
	// The learned model already sees every use signal; its temperature was fitted on held-out apps
	// with the same full-context features, so the probabilities are the measured ones (no extra rule votes).
	p := Softmax(model.Logits(s.Features(-1)), model.TempFull)
	name := fmt.Sprintf("smalirole-lr-v1 (%d features, T=%.2f, calibrated on held-out apps)", len(model.Features), model.TempFull)
	if model.Graph != nil {
		pg := model.Graph.Predict(s.Graph(-1))[0]
		for i := range p {
			p[i] = 0.5*p[i] + 0.5*pg[i]
		}
		name += " + smalirole-gnn (R-GCN over the def-use graph, ensemble 50/50)"
	}
	// A use that reaches a typed timing API (postDelayed, setDuration, setReadTimeout …) is direct evidence.
	// That rule was hand-audited on the corpus (v0.4: 40/40 sampled labels correct, 95% CI lower bound 0.91),
	// so its audited precision is mixed in instead of trusting only the model, which rarely saw the rule
	// fire through fields or callees.
	// Deterministic facts from a real-APK audit: Build.VERSION.SDK_INT comparisons take an API level,
	// UPPER_SNAKE *_REASON_/*_TYPE_ constants are codes. Both override the model (it never saw these signals).
	if k, prec := apiFact(s.Sigs); k >= 0 {
		for i := range p {
			p[i] *= 1 - prec
		}
		p[k] += prec
		return p, name + " + API-level/enum-code rule"
	}
	// A literal returned directly by getMaxCoins()/getTimeoutMs()… is named by the method itself.
	// The model never saw the method's own name; this rule is NOT audited yet, so it is mixed in at 0.6.
	if k := selfNameFact(s.Sigs); k >= 0 {
		for i := range p {
			p[i] *= 1 - SelfNameWeight
		}
		p[k] += SelfNameWeight
		name += fmt.Sprintf(" + method-name rule (unaudited, weight %.1f)", SelfNameWeight)
	}
	if l, _ := Oracle(s.Sigs, s.V, false, s.Method); l == "duration_ms" {
		k := labelIndex(l)
		for i := range p {
			p[i] *= 1 - AuditedTimingPrecision
		}
		p[k] += AuditedTimingPrecision
		name += fmt.Sprintf(" + typed timing sink (audited precision %.2f)", AuditedTimingPrecision)
	}
	return p, name
}

func apiFact(sigs [][]string) (int, float64) {
	for _, sg := range sigs {
		for _, t := range sg {
			switch strings.TrimPrefix(t, "callee:") {
			case "cmpwith:sdk_int":
				return labelIndex("api_constant"), 0.99
			case "field:enum_code":
				return labelIndex("api_constant"), 0.9
			}
		}
	}
	return -1, 0
}

// SDKLevel returns the API level when the literal is compared with Build.VERSION.SDK_INT.
func (r *Report) SDKLevel() bool { return hasTag(r.Evidence, "cmpwith:sdk_int") }

// AuditedTimingPrecision is the conservative (Wilson 95% lower bound) precision of the duration_ms sink rule
// from the manual audit in TEST-REPORT.md.
const AuditedTimingPrecision = 0.91

// Analyze answers for the const on Request.Line. model and resolve may be nil.
func Analyze(r Request, model *Model, resolve Resolver) (Report, error) {
	return AnalyzeCtx(r, model, &Ctx{Resolve: resolve})
}

// AnalyzeCtx analyzes with app-wide lookups (callees and field reads). Class names the method's class
// so field references to the same class resolve; leave empty for standalone snippets.
func AnalyzeCtx(r Request, model *Model, ctx *Ctx) (Report, error) {
	m := ParseMethod(r.Class, r.Code)
	idx := -1
	for i, in := range m.Insns {
		if in.Line == r.Line {
			idx = i
		}
	}
	if idx < 0 {
		return Report{}, fmt.Errorf("line %d is not an instruction", r.Line)
	}
	s, ok := NewSiteCtx(m, idx, ctx)
	if !ok {
		return Report{}, fmt.Errorf("line %d is not a const literal instruction", r.Line)
	}
	return report(s, r, model), nil
}

func report(s *Site, r Request, model *Model) Report {
	p, scorer := Score(s, model)
	rep := Report{Version: Version, ConstLine: s.Method.Insns[s.Index].Line, Register: s.Reg, Literal: s.Literal, Int32: s.V, Uint32: s.U, Scorer: scorer, Evidence: []Evidence{}, Wide: s.Wide}
	for i, l := range Labels {
		rep.Probs = append(rep.Probs, Prob{l, math.Round(p[i]*1000) / 1000})
	}
	sort.SliceStable(rep.Probs, func(i, j int) bool { return rep.Probs[i].P > rep.Probs[j].P })
	for i, u := range s.Uses {
		rep.Evidence = append(rep.Evidence, Evidence{Line: u.Insn.Line, Text: u.Insn.Raw, Via: u.Via, Tags: s.Sigs[i], Signal: describe(s.Sigs[i])})
	}
	rep.Threshold = 0.6
	if r.Threshold != nil {
		rep.Threshold = *r.Threshold
	}
	rep.Answer, rep.Confidence = rep.Probs[0].Label, rep.Probs[0].P
	rep.TimeUnit = HasTimeUnit(s.Sigs)
	rep.Stored = s.StoredFields()
	if IsFloatUse(s.Sigs) {
		f := float64(math.Float32frombits(uint32(s.U)))
		if s.Wide {
			f = math.Float64frombits(s.U)
		}
		rep.FloatValue = &f
		rep.Confidence = 0 // the int-role schema does not apply to float bits
	}
	if rep.Confidence < rep.Threshold || rep.Answer == "unknown" {
		rep.Abstained, rep.Answer = true, "unknown"
	}
	rep.Explanation = Explain(&rep)
	return rep
}

// SelfNameWeight is the probability mass given to the method-name rule (not audited on the corpus).
const SelfNameWeight = 0.6

// selfNameFact returns the label voted by the returning method's own name tokens, or -1.
func selfNameFact(sigs [][]string) int {
	z := make([]float64, len(Labels))
	any := false
	for _, sg := range sigs {
		for _, x := range sg {
			if strings.HasPrefix(x, "ret:self:tok:") {
				for l, w := range expertVotes[x] {
					z[labelIndex(l)] += w
					any = true
				}
			}
		}
	}
	if !any {
		return -1
	}
	best, second := 0, -1
	for i := range z {
		if z[i] > z[best] {
			best = i
		}
	}
	for i := range z {
		if i != best && (second < 0 || z[i] > z[second]) {
			second = i
		}
	}
	if z[best] < 2 || (second >= 0 && z[best]-z[second] < 1) {
		return -1 // conflicting names (getMaxDelay) — let the model decide
	}
	return best
}

// NameVote returns the role suggested by a method name alone (getMaxCoins → limit_threshold),
// for callers that know the method but not its code. ok=false when the name is silent or conflicting.
func NameVote(method string) (string, bool) {
	var sg []string
	for _, t := range camelTokens(method) {
		sg = append(sg, "ret:self:tok:"+t)
	}
	if k := selfNameFact([][]string{sg}); k >= 0 {
		return Labels[k], true
	}
	return "", false
}
