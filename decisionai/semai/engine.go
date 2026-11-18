// Package semai is DecisionAI's semantic engine: it answers by *meaning*, not by word overlap.
//
// Three layers work together and are all CPU-only, stdlib-only and offline:
//  1. a Transformer encoder (encoder.go) that embeds clauses and aligns them (cross-attention-like
//     late interaction) — used for yes/no decisions against free-text criteria;
//  2. a semantic frame layer: option parsing, quantity/number understanding, a small part-whole knowledge
//     base and an arithmetic evaluator;
//  3. an ambiguity-aware decision layer: every question is expanded into weighted *readings*; if the readings
//     disagree about the answer the engine says "unknown" instead of guessing.
package semai

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const Version = "0.6.0"

type Request struct {
	ID        string   `json:"id,omitempty"`
	Question  string   `json:"question"`
	Options   []string `json:"options,omitempty"`
	State     string   `json:"state,omitempty"`
	TrueWhen  string   `json:"true_when,omitempty"`
	FalseWhen string   `json:"false_when,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`
}

type Candidate struct {
	Label string   `json:"label"`
	Text  string   `json:"text"`
	Prob  float64  `json:"probability"`
	Value *float64 `json:"value,omitempty"`
}
type ReadingOut struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Detail  string  `json:"detail"`
	Weight  float64 `json:"weight"`
	Result  string  `json:"result"`
	Option  string  `json:"option,omitempty"`
	Matches bool    `json:"matches_option"`
}
type NeuralInfo struct {
	Enabled  bool   `json:"enabled"`
	Model    string `json:"model,omitempty"`
	Layers   int    `json:"layers,omitempty"`
	Heads    int    `json:"heads,omitempty"`
	Hidden   int    `json:"hidden,omitempty"`
	NLI      bool   `json:"nli_cross_encoder"`
	NLIModel string `json:"nli_model,omitempty"`
	Note     string `json:"note,omitempty"`
}
type Report struct {
	Version     string       `json:"version"`
	ID          string       `json:"id,omitempty"`
	Kind        string       `json:"kind"`   // choice | yesno | open
	Solver      string       `json:"solver"` // part_count | arithmetic | criteria | context | none
	Stem        string       `json:"stem,omitempty"`
	Answer      string       `json:"answer"` // option label, yes/no, a value or unknown
	AnswerText  string       `json:"answer_text,omitempty"`
	Verdict     string       `json:"verdict"` // answer | unknown
	Confidence  float64      `json:"confidence"`
	Threshold   float64      `json:"threshold"`
	Candidates  []Candidate  `json:"candidates"`
	Readings    []ReadingOut `json:"readings,omitempty"`
	Alignments  []Alignment  `json:"alignments,omitempty"`
	Reasoning   []string     `json:"reasoning"`
	Abstention  []string     `json:"abstention_reasons"`
	Warnings    []string     `json:"warnings"`
	Neural      NeuralInfo   `json:"neural"`
	ElapsedMs   float64      `json:"elapsed_ms"`
	PossibleSet []string     `json:"possible_answers,omitempty"`
}

func Validate(r Request) error {
	for k, v := range map[string]string{"question": r.Question, "state": r.State, "true_when": r.TrueWhen, "false_when": r.FalseWhen} {
		if len(v) > 32768 {
			return fmt.Errorf("%s is longer than 32768 bytes", k)
		}
	}
	if len(r.Options) > 12 {
		return fmt.Errorf("at most 12 options")
	}
	if strings.TrimSpace(r.Question) == "" && strings.TrimSpace(r.State) == "" {
		return fmt.Errorf("question is required")
	}
	if r.Threshold != nil && (math.IsNaN(*r.Threshold) || *r.Threshold < 0.5 || *r.Threshold > 1) {
		return fmt.Errorf("threshold must be in [0.5,1]")
	}
	return nil
}

func neuralInfo(enc *Encoder) NeuralInfo {
	if enc == nil {
		return NeuralInfo{Enabled: false, Note: "Transformer-энкодер не загружен: работает только символьный слой и лексика."}
	}
	ni := NeuralInfo{Enabled: true, Model: enc.Source, Layers: len(enc.layers), Heads: enc.nHead, Hidden: enc.hidden}
	if c := crossOf(enc); c != nil {
		ni.NLI = true
		ni.NLIModel = c.Source
	} else {
		ni.Note = "NLI-классификатор (cross-encoder) не загружен: смысл сравнивается по эмбеддингам, это слабее."
	}
	return ni
}

// Analyze answers a request. enc may be nil (the symbolic layer still works).
func Analyze(req Request, enc *Encoder) (Report, error) {
	t0 := time.Now()
	if err := Validate(req); err != nil {
		return Report{}, err
	}
	rep := Report{Version: Version, ID: req.ID, Answer: "unknown", Verdict: "unknown", Neural: neuralInfo(enc), Solver: "none",
		Candidates: []Candidate{}, Reasoning: []string{}, Abstention: []string{}, Warnings: []string{}}
	stemText, opts := ParseChoices(req.Question, req.Options)
	rep.Stem = stemText
	hasCrit := strings.TrimSpace(req.TrueWhen) != "" || strings.TrimSpace(req.FalseWhen) != ""
	switch {
	case len(opts) >= 2:
		rep.Kind = "choice"
	case hasCrit:
		rep.Kind = "yesno"
	default:
		rep.Kind = "open"
	}
	thr := 0.6
	if rep.Kind == "yesno" {
		thr = 0.7
	}
	if req.Threshold != nil {
		thr = *req.Threshold
	}
	rep.Threshold = thr

	if fa := SolveFacts(req.State, req.Question); fa != nil && len(opts) < 2 {
		rep.Reasoning = append(rep.Reasoning, fa.Reasoning...)
		if fa.Answer != "unknown" {
			rep.Kind, rep.Solver, rep.Answer, rep.Verdict, rep.Confidence = "yesno", "facts", fa.Answer, "answer", fa.Confidence
			if len(fa.Who) > 0 {
				rep.AnswerText = strings.Join(fa.Who, ", ")
			}
			rep.ElapsedMs = float64(time.Since(t0).Microseconds()) / 1000
			return rep, nil
		}
	}
	if rep.Kind == "yesno" {
		analyzeYesNo(&rep, req, enc)
	} else {
		var oc *outcome
		if oc = solveArithmetic(stemText); oc == nil {
			oc = solvePartCount(stemText)
		}
		if oc == nil && rep.Kind == "choice" && strings.TrimSpace(req.State) != "" {
			analyzeContext(&rep, req, stemText, opts, enc)
		} else if oc == nil {
			rep.Abstention = append(rep.Abstention, "no_semantic_frame")
			rep.Reasoning = append(rep.Reasoning, "Я не распознал, о чём вопрос: нет ни арифметики, ни знакомой схемы «часть — целое», ни контекста (state) с критериями. Угадывать по тексту не буду.")
			if rep.Kind == "choice" {
				for _, o := range opts {
					rep.Candidates = append(rep.Candidates, Candidate{Label: o.Label, Text: o.Text, Value: o.Value})
				}
			}
		} else {
			decideFromOutcome(&rep, oc, opts, thr)
		}
	}
	if rep.Kind == "choice" && rep.Answer == "unknown" {
		for _, o := range opts {
			if o.IsUnknown {
				rep.Answer, rep.AnswerText = o.Label, o.Text
				for i := range rep.Candidates {
					if rep.Candidates[i].Label == o.Label {
						rep.Candidates[i].Prob = rep.Confidence
					}
				}
				rep.Reasoning = append(rep.Reasoning, "Среди вариантов есть «"+o.Text+"» — это и есть верный ответ при такой неоднозначности.")
				break
			}
		}
	}
	rep.ElapsedMs = float64(time.Since(t0).Microseconds()) / 1000
	return rep, nil
}

func valueText(v float64) string { return fmtNum(round9(v)) }

func decideFromOutcome(rep *Report, oc *outcome, opts []Option, thr float64) {
	rep.Solver = oc.Solver
	rep.Reasoning = append(rep.Reasoning, oc.Notes...)
	if oc.Failure != "" {
		code := oc.FailCode
		if code == "" {
			code = "no_knowledge"
		}
		rep.Abstention = append(rep.Abstention, code)
		rep.Reasoning = append(rep.Reasoning, oc.Failure)
		for _, o := range opts {
			rep.Candidates = append(rep.Candidates, Candidate{Label: o.Label, Text: o.Text, Value: o.Value})
		}
		return
	}
	// aggregate weight per answer value
	type agg struct {
		val float64
		w   float64
	}
	var vals []agg
	for _, r := range oc.Readings {
		found := false
		for i := range vals {
			if math.Abs(vals[i].val-r.Val) < 1e-9 {
				vals[i].w += r.W
				found = true
			}
		}
		if !found {
			vals = append(vals, agg{r.Val, r.W})
		}
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i].w > vals[j].w })
	optFor := func(v float64) *Option {
		for i := range opts {
			if opts[i].Value != nil && math.Abs(*opts[i].Value-v) < 1e-9 {
				return &opts[i]
			}
		}
		return nil
	}
	for _, r := range oc.Readings {
		ro := ReadingOut{ID: r.ID, Title: r.Title, Detail: r.Detail, Weight: r.W, Result: valueText(r.Val)}
		if o := optFor(r.Val); o != nil {
			ro.Option, ro.Matches = o.Label, true
		}
		rep.Readings = append(rep.Readings, ro)
	}
	if len(vals) > 1 {
		for _, v := range vals {
			rep.PossibleSet = append(rep.PossibleSet, valueText(v.val))
		}
	}

	if rep.Kind == "open" {
		for _, v := range vals {
			vv := v.val
			rep.Candidates = append(rep.Candidates, Candidate{Label: valueText(v.val), Text: valueText(v.val), Prob: v.w, Value: &vv})
		}
		top := vals[0]
		if top.w*oc.Certainty >= thr {
			rep.Answer, rep.AnswerText, rep.Verdict, rep.Confidence = valueText(top.val), valueText(top.val), "answer", top.w*oc.Certainty
			rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("Все допустимые прочтения вопроса дают один ответ: %s%s.", valueText(top.val), unitSuffix(oc)))
		} else {
			rep.Abstention = append(rep.Abstention, "ambiguous_question")
			rep.Confidence = 1 - top.w
			rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("Вопрос допускает несколько разумных прочтений с разными ответами (%s). Выбирать один — значит угадывать.", strings.Join(rep.PossibleSet, ", ")))
		}
		return
	}

	// multiple choice
	probs := make([]float64, len(opts))
	matched := 0.0
	for _, r := range oc.Readings {
		if o := optFor(r.Val); o != nil {
			for i := range opts {
				if opts[i].Label == o.Label {
					probs[i] += r.W
				}
			}
			matched += r.W
		}
	}
	for i, o := range opts {
		c := Candidate{Label: o.Label, Text: o.Text, Value: o.Value}
		if matched > 0 {
			c.Prob = probs[i] / matched
		}
		rep.Candidates = append(rep.Candidates, c)
	}
	if matched == 0 {
		rep.Abstention = append(rep.Abstention, "no_option_matches")
		rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("Ни одно из прочтений не даёт ни одного из предложенных вариантов (получается: %s). Либо вариантов не хватает, либо вопрос понят иначе.", strings.Join(possibleOrTop(rep.PossibleSet, vals[0].val), ", ")))
		return
	}
	best := 0
	for i := range probs {
		if probs[i] > probs[best] {
			best = i
		}
	}
	top := probs[best] / matched
	conf := top * (0.5 + 0.5*matched) * oc.Certainty
	if matched < 0.999 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%.0f%% прочтений дают значение, которого нет среди вариантов — уверенность снижена.", (1-matched)*100))
	}
	if conf >= thr {
		rep.Answer, rep.AnswerText, rep.Verdict, rep.Confidence = opts[best].Label, opts[best].Text, "answer", conf
		rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("Вариант %s совпадает с результатом %.0f%% правдоподобных прочтений.", opts[best].Label, top*100))
		return
	}
	rep.Abstention = append(rep.Abstention, "ambiguous_question")
	rep.Confidence = clamp(1-top, 0, 1)
	var parts []string
	for _, c := range rep.Candidates {
		if c.Prob > 0 {
			parts = append(parts, fmt.Sprintf("%s — %.0f%%", c.Label, c.Prob*100))
		}
	}
	rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("Прочтения расходятся: %s. Ни один вариант не набирает порог %.0f%%, поэтому ответ — unknown.", strings.Join(parts, ", "), rep.Threshold*100))
}

func possibleOrTop(set []string, top float64) []string {
	if len(set) > 0 {
		return set
	}
	return []string{valueText(top)}
}
func unitSuffix(oc *outcome) string {
	if oc.Unit != "" {
		return " (" + oc.Unit + ")"
	}
	return ""
}

// analyzeYesNo: state + true_when / false_when → yes / no / unknown with Transformer-based alignment.
func analyzeYesNo(rep *Report, req Request, enc *Encoder) {
	rep.Solver = "criteria"
	if strings.TrimSpace(req.State) == "" {
		rep.Abstention = append(rep.Abstention, "no_state")
		rep.Reasoning = append(rep.Reasoning, "Нет описания состояния (state): сравнивать критерии не с чем.")
		rep.Candidates = []Candidate{{Label: "yes", Text: "yes"}, {Label: "no", Text: "no"}, {Label: "unknown", Text: "unknown", Prob: 1}}
		rep.Confidence = 1
		return
	}
	state := prepClauses(clauses(req.State), enc)
	neural := enc != nil
	ctx := critCtx{enc: enc, cross: crossOf(enc), state: state, whole: strings.TrimSpace(req.State), neural: neural}
	if !neural {
		rep.Warnings = append(rep.Warnings, "Энкодер не загружен — сопоставление идёт только по лексике, это заметно слабее.")
	}
	t := alignSet("true_when", req.TrueWhen, ctx)
	f := alignSet("false_when", req.FalseWhen, ctx)
	rep.Alignments = append(append([]Alignment{}, t.aligns...), f.aligns...)
	py, pn, pu := yesNoProbs(t, f)
	rep.Candidates = []Candidate{{Label: "yes", Text: "yes", Prob: py}, {Label: "no", Text: "no", Prob: pn}, {Label: "unknown", Text: "unknown", Prob: pu}}
	for _, a := range rep.Alignments {
		switch a.Relation {
		case "supports":
			rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("«%s» ↔ «%s»: по смыслу совпадает (%.0f%%), полярность та же.", a.Criterion, a.State, a.Strength*100))
		case "contradicts":
			rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("«%s» ↔ «%s»: тема совпадает (%.0f%%), но утверждение противоположное.", a.Criterion, a.State, a.Strength*100))
		default:
			rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("«%s»: в state нет близкого по смыслу утверждения.", a.Criterion))
		}
	}
	best, label := pu, "unknown"
	if py > best {
		best, label = py, "yes"
	}
	if pn > best {
		best, label = pn, "no"
	}
	if label != "unknown" && best >= rep.Threshold {
		rep.Answer, rep.Verdict, rep.Confidence = label, "answer", best
	} else {
		rep.Answer, rep.Verdict, rep.Confidence = "unknown", "unknown", pu
		switch {
		case math.Min(py, pn) > 0.2:
			rep.Abstention = append(rep.Abstention, "conflicting_evidence")
		case t.cover == 0 && f.cover == 0:
			rep.Abstention = append(rep.Abstention, "no_matching_evidence")
		default:
			rep.Abstention = append(rep.Abstention, "confidence_below_threshold")
		}
	}
	rep.AnswerText = rep.Answer
}

// analyzeContext: choice question answered from a free-text state. Weak evidence, so it stays conservative.
func analyzeContext(rep *Report, req Request, stemText string, opts []Option, enc *Encoder) {
	rep.Solver = "context"
	state := prepClauses(clauses(req.State), enc)
	q := clauseEnc{text: stemText, stems: contentStems(stemText), pol: 1}
	if enc != nil {
		q.enc = enc.Encode(stemText)
	}
	scores := make([]float64, len(opts))
	for i, o := range opts {
		oc := prepClauses([]string{stemText + " " + o.Text}, enc)[0]
		for _, s := range state {
			if _, _, _, sc := scorePair(oc, s); sc > scores[i] {
				scores[i] = sc
			}
		}
		// literal presence of the option text in the state is strong evidence
		if o.Text != "" && strings.Contains(normText(req.State), normText(o.Text)) {
			scores[i] += 0.15
		}
	}
	z, ex := 0.0, make([]float64, len(opts))
	for i, s := range scores {
		ex[i] = math.Exp(10 * s)
		z += ex[i]
	}
	best := 0
	for i := range opts {
		c := Candidate{Label: opts[i].Label, Text: opts[i].Text, Value: opts[i].Value, Prob: ex[i] / z}
		rep.Candidates = append(rep.Candidates, c)
		if scores[i] > scores[best] {
			best = i
		}
	}
	margin := rep.Candidates[best].Prob
	rep.Warnings = append(rep.Warnings, "Ответ из свободного контекста — слабое свидетельство; использую только при явном преимуществе.")
	if scores[best] >= 0.6 && margin >= rep.Threshold {
		rep.Answer, rep.AnswerText, rep.Verdict, rep.Confidence = opts[best].Label, opts[best].Text, "answer", margin
		rep.Reasoning = append(rep.Reasoning, fmt.Sprintf("Вариант %s ближе всего по смыслу к утверждениям из state.", opts[best].Label))
		return
	}
	rep.Abstention = append(rep.Abstention, "weak_context_evidence")
	rep.Confidence = 1 - margin
	rep.Reasoning = append(rep.Reasoning, "Контекст не выделяет ни один вариант достаточно чётко.")
}
