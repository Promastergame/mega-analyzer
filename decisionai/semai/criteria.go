package semai

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

var negWords = map[string]bool{}
var negLex = []string{"ошиб", "сбой", "сбои", "провал", "неудач", "fail", "error", "отсутств", "упал", "crash", "broke", "сломан", "отказ", "reject", "denied", "invalid", "неверн", "неправильн", "ложн", "false", "неуспеш", "невозмож", "отклон", "нарушен", "mismatch", "несовпад", "не совпад", "stale", "устарел", "regress", "ухудш", "отмен", "cancel", "abort", "timeout", "таймаут", "неисправ", "дефект", "поврежд", "corrupt", "вирус", "malware", "взлом", "breach", "undefined", "missing"}

func init() {
	for _, w := range strings.Fields(`не нет ни без никогда нельзя not no never cannot can't isn't aren't wasn't weren't didn't don't doesn't won't couldn't shouldn't hasn't haven't hadn't without none nothing nobody nowhere neither nor`) {
		negWords[w] = true
	}
}

// polarity: +1 affirmative, -1 negated. It is the parity of negation markers and negative-lexicon words,
// so "нет ошибок" (two markers) stays affirmative and "не прошёл" (one) is negative.
func polarity(clause string) int {
	n := 0
	for _, t := range tokens(clause) {
		if negWords[t] || strings.HasSuffix(t, "n't") {
			n++
			continue
		}
		for _, p := range negLex {
			if strings.HasPrefix(t, p) {
				n++
				break
			}
		}
	}
	if n%2 == 1 {
		return -1
	}
	return 1
}

// Alignment is the semantic match between one criterion clause and the best clause of the state.
type Alignment struct {
	Role      string  `json:"role"`
	Criterion string  `json:"criterion"`
	State     string  `json:"best_state_clause"`
	Cosine    float64 `json:"sentence_similarity"`
	TokenSim  float64 `json:"token_similarity"`
	Lexical   float64 `json:"lexical_overlap"`
	Score     float64 `json:"score"`
	Strength  float64 `json:"strength"`
	CritPol   int     `json:"criterion_polarity"`
	StatePol  int     `json:"state_polarity"`
	Relation  string  `json:"relation"` // supports | contradicts | unrelated
	Signed    float64 `json:"signed_evidence"`
	NLI       *NLI    `json:"nli,omitempty"`
}

type clauseEnc struct {
	text  string
	enc   *Encoding
	stems []string
	pol   int
}

func prepClauses(texts []string, enc *Encoder) []clauseEnc {
	out := make([]clauseEnc, 0, len(texts))
	for _, t := range texts {
		c := clauseEnc{text: t, stems: contentStems(t), pol: polarity(t)}
		if enc != nil {
			c.enc = enc.Encode(t)
		}
		out = append(out, c)
	}
	return out
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

// scorePair combines Transformer sentence similarity, token-level (late-interaction) similarity and
// lexical overlap into a single 0..1 relatedness score.
func scorePair(c, s clauseEnc) (cos, tok, lex, score float64) {
	lex = math.Max(overlapCoverage(c.stems, s.stems), 0)
	if c.enc == nil || s.enc == nil {
		return 0, 0, lex, lex
	}
	cos = Cosine(c.enc.CLS, s.enc.CLS)
	tok = (MaxSim(c.enc, s.enc) + MaxSim(s.enc, c.enc)) / 2
	score = 0.45*cos + 0.35*tok + 0.20*lex
	return
}

// Calibrated on tests (see TEST-REPORT): below `relLo` a clause is unrelated, above `relHi` it is a clear match.
const relLoNeural, relHiNeural = 0.62, 0.84
const relLoLex, relHiLex = 0.3, 0.75

type critResult struct {
	signed float64 // -1..1
	aligns []Alignment
	cover  float64
}

// ---- criterion structure: AND of sentences, each an OR of alternatives, each an AND of atomic claims ----

type critCtx struct {
	enc     *Encoder // bi-encoder (sentence + token vectors)
	cross   *Encoder // NLI cross-encoder, may be nil
	state   []clauseEnc
	whole   string
	neural  bool
	role    string
	aligns  []Alignment
	atomsN  int
	covered int
}

var orSplit = regexp.MustCompile(`\s+(?:или|либо|or)\s+`)
var andSplit = regexp.MustCompile(`\s*(?:,\s*и\s+|,\s*and\s+|\s+и\s+|\s+and\s+|;)\s*`)

func fewWords(s string) bool { return len(strings.Fields(s)) < 2 }

func splitKeep(re *regexp.Regexp, s string) []string {
	parts := re.Split(s, -1)
	if len(parts) < 2 {
		return []string{s}
	}
	// glue back fragments that are too short to be a claim ("хлеб и молоко")
	var out []string
	cur := parts[0]
	for _, p := range parts[1:] {
		if fewWords(cur) || fewWords(p) {
			cur = cur + " " + p
			continue
		}
		out = append(out, cur)
		cur = p
	}
	return append(out, cur)
}

// evalCriterion returns the signed support (-1..1) of a criterion text given the state.
func (c *critCtx) evalCriterion(text string) float64 {
	sentences := clauses(text)
	if len(sentences) == 0 {
		return 0
	}
	val := math.Inf(1)
	for _, sent := range sentences {
		alts := splitKeep(orSplit, sent)
		best := math.Inf(-1)
		for _, alt := range alts {
			atoms := splitKeep(andSplit, alt)
			av := math.Inf(1)
			for _, at := range atoms {
				if v := c.atom(strings.TrimSpace(at)); v < av {
					av = v
				}
			}
			if av > best {
				best = av
			}
		}
		if best < val {
			val = best
		}
	}
	return val
}

// atom scores one claim against the state. With the NLI cross-encoder, the claim is the hypothesis and
// (the best state clauses | the whole state) is the premise: P(entail) - P(contradict) is the signed evidence.
func (c *critCtx) atom(text string) float64 {
	cl := prepClauses([]string{text}, c.enc)[0]
	lo, hi := relLoNeural, relHiNeural
	if !c.neural {
		lo, hi = relLoLex, relHiLex
	}
	type cand struct {
		idx   int
		score float64
	}
	var cands []cand
	for i, s := range c.state {
		_, _, _, sc := scorePair(cl, s)
		cands = append(cands, cand{i, sc})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	best := Alignment{Role: c.role, Criterion: text, CritPol: cl.pol, Relation: "unrelated"}
	if len(cands) > 0 {
		s := c.state[cands[0].idx]
		best.Cosine, best.TokenSim, best.Lexical, best.Score = 0, 0, 0, cands[0].score
		best.Cosine, best.TokenSim, best.Lexical, _ = scorePair(cl, s)
		best.State, best.StatePol = s.text, s.pol
	}
	best.Strength = clamp((best.Score-lo)/(hi-lo), 0, 1)
	// heuristic signed evidence (embedding relatedness x negation parity)
	heur := 0.0
	if best.Strength > 0.05 {
		heur = best.Strength
		if best.CritPol != best.StatePol {
			heur = -heur
		}
	}
	signed := heur
	if c.cross != nil && len(cands) > 0 {
		premises := []string{}
		for k := 0; k < len(cands) && k < 2; k++ {
			premises = append(premises, c.state[cands[k].idx].text)
		}
		if len(c.state) > 1 {
			premises = append(premises, c.whole)
		}
		bestAbs, bestN, bestP := -1.0, NLI{}, ""
		for _, p := range premises {
			n := c.cross.Classify(p, text)
			if v := math.Abs(n.Entailment - n.Contradiction); v > bestAbs {
				bestAbs, bestN, bestP = v, n, p
			}
		}
		nv := bestN.Entailment - bestN.Contradiction
		// the NLI verdict leads; the heuristic only adds weight when it agrees
		signed = nliWeight*nv + (1-nliWeight)*heur
		// near-verbatim restatement: trust the lexical identity (the tiny NLI model is shaky on unseen sentences)
		if best.Lexical >= 0.85 && len(cl.stems) >= 2 && best.Strength > 0.5 {
			sign := 1.0
			if best.CritPol != best.StatePol {
				sign = -1
			}
			signed = 0.35*nv + 0.65*sign*math.Max(best.Strength, 0.9)
		}
		best.NLI = &bestN
		if bestP != c.whole {
			best.State = bestP
		} else {
			best.State = "(весь state целиком)"
		}
	}
	c.atomsN++
	switch {
	case signed > 0.15:
		best.Relation = "supports"
	case signed < -0.15:
		best.Relation = "contradicts"
	default:
		best.Relation = "unrelated"
	}
	if math.Abs(signed) > 0.25 {
		c.covered++
	}
	best.Signed = signed
	c.aligns = append(c.aligns, best)
	return signed
}

const nliWeight = 0.8

func alignSet(role, text string, ctx critCtx) critResult {
	ctx.role = role
	ctx.aligns, ctx.atomsN, ctx.covered = nil, 0, 0
	if strings.TrimSpace(text) == "" {
		return critResult{}
	}
	v := ctx.evalCriterion(text)
	r := critResult{signed: v, aligns: ctx.aligns}
	if ctx.atomsN > 0 {
		r.cover = float64(ctx.covered) / float64(ctx.atomsN)
	}
	if math.IsInf(v, 0) {
		r.signed = 0
	}
	return r
}

// yesNoProbs fuses evidence for the true_when / false_when criteria into P(yes), P(no), P(unknown).
func yesNoProbs(t, f critResult) (py, pn, pu float64) {
	// A contradicted criterion only *rules out* its own answer, so it counts for the opposite answer at half weight.
	y := math.Max(t.signed, 0) + 0.5*math.Max(-f.signed, 0)
	n := math.Max(f.signed, 0) + 0.5*math.Max(-t.signed, 0)
	cov := math.Max(t.cover, f.cover)
	lu := 1.5 + 2.5*(1-cov) + 3*math.Min(y, n)
	ey, en, eu := math.Exp(4*y), math.Exp(4*n), math.Exp(lu)
	z := ey + en + eu
	return ey / z, en / z, eu / z
}
