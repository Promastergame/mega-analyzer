package s1

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"decisionai/vision"
)

// Engine evaluates every question of a request against one state in a single batched pass.
type Engine struct {
	Vision  vision.Describer
	Backend Backend
	// Escalate, when set, re-asks uncertain answers from a remote System Two model
	// (Jev / Span-01 via OpenRouter decisions API) — see escalate.go.
	Escalate *Escalator
	// Experts are tried in order before the general backend; the first that recognises a question answers it.
	Experts []Expert
	// NoLex disables lexical evidence fusion (concept lexicon + description overlap) in the general path.
	NoLex bool
	// LexScale multiplies LexWeight per question type (nil / missing = 1). The distilled
	// encoder already carries most lexical signal, so it is fused with a lighter hand.
	LexScale map[string]float64
	// Skills, when set, expands task=skill_routing questions that arrive
	// without criteria: the registry becomes the options, the winner's
	// SKILL.md path is attached as a source reference.
	Skills *SkillRegistry
	// SkillBackend, when set, scores the hypotheses of skill_routing questions
	// (the general Backend scores everything else). v1.7 ships the distilled
	// cross-encoder as Backend and keeps the bi-encoder for skill routing, whose
	// lexical fusion and calibration were fitted on it.
	SkillBackend Backend
	// SkillBackendLoader supplies the skill model on demand when SkillBackend
	// is nil. It is shared by engine copies; Decide never mutates SkillBackend.
	SkillBackendLoader *BackendLoader
	Calib              Calibration
	// NoPlan disables multi-step skill plans (also set on clause sub-engines).
	NoPlan           bool
	ModelName        string
	MaxChunkWords    int
	MaxChunkTokens   int
	MaxChunks        int
	MaxPairs         int
	ModelFingerprint string
	// Hashes of externally configured expert/skill weights, set before serving.
	AuxiliaryFingerprint string
	contextCache         *contextIndexCache
}

func NewEngine(b Backend, c Calibration) *Engine {
	return &Engine{Vision: vision.Local{}, Backend: b, Calib: c, ModelName: "dai-s1-" + Version, MaxChunkWords: 45, MaxChunkTokens: 128, MaxChunks: 12, MaxPairs: 4096, ModelFingerprint: backendFingerprint(b), contextCache: &contextIndexCache{entries: weightedCache[[32]byte, *contextIndex]{limit: DefaultContextCacheBytes}}}
}

const eps = 0.01

// minSubstantiveSupport is the entailment level at which a declared option
// counts as backed by evidence. Below it the question is treated as
// unsupported: abstain/escape options may win and the route stays human.
const minSubstantiveSupport = 0.2

// ExampleMinSupport: a few-shot example only steers ranking when the request
// is a near-paraphrase of it; looser similarity is noise between short texts.
var ExampleMinSupport = 0.9

// MinCalibrationN is the minimum number of labelled answers of a type before "auto" routing is allowed.
const MinCalibrationN = 50

type plan struct {
	q              compiled
	slots          []int // index into hypotheses, -1 for an escape option
	escape         []bool
	extra          [][]int // skill routing: few-shot example hypotheses per option
	exHit          []string
	primary        []int // description slots; abstention is judged on these, not on examples
	contextMissing bool
}

var escapeWords = []string{"other", "none", "neither", "nothing", "unknown", "n/a", "другое", "ничего", "иное", "прочее", "нет подходящ", "не определ", "cannot be determined"}

func isEscape(o Option) bool {
	for _, part := range []string{o.Key, o.Text} {
		k := strings.ToLower(strings.TrimSpace(part))
		for _, w := range escapeWords {
			if k == w {
				return true
			}
		}
		if strings.HasPrefix(k, "none of ") || strings.HasPrefix(k, "ни один") {
			return true
		}
	}
	return false
}

func statement(instr string) string {
	s := strings.TrimSpace(instr)
	s = strings.TrimRight(s, "?. ")
	return s
}

func optionHypothesis(instr string, o Option) string {
	t := strings.TrimSpace(strings.TrimRight(o.Text, ". "))
	if len(strings.Fields(t)) >= 4 {
		return t
	}
	return statement(instr) + ": " + t
}

// Decide runs the request. The returned answers only ever contain declared keys.
func (e *Engine) Decide(r Request) (Response, error) {
	return e.DecideContext(context.Background(), r)
}

func (e *Engine) decideTextContext(ctx context.Context, r Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	start := time.Now()
	state, qs, err := r.compile()
	if err != nil {
		return Response{}, err
	}
	if err := e.expandSkills(state, &qs); err != nil {
		return Response{}, err
	}
	resp := Response{Version: Version, Model: e.ModelName, Backend: e.Backend.Name(), Answers: map[string]Answer{}}
	if len(e.Experts) > 0 {
		sv := decodeState(r.State)
		rest := qs[:0:0]
		for _, q := range qs {
			eq := ExpertQuestion{ID: q.ID, Type: q.Type, Instr: q.Instr, Options: q.Options, Task: q.Task, Polarity: q.Polarity, AbstainKey: q.AbstainKey, Claim: q.Claim}
			done := false
			for _, ex := range e.Experts {
				ea, ok := ex.Answer(sv, state, eq)
				if !ok {
					continue
				}
				if ea.Source == "" {
					ea.Source = ex.Name()
				}
				if a, ok := expertAnswer(q, ea); ok {
					if a.Neural != nil {
						resp.Usage.ModelCalls += a.Neural.ForwardPasses
					}
					e.attachSkillPath(q, &a)
					resp.Answers[q.ID], done = a, true
					break
				}
			}
			if !done {
				rest = append(rest, q)
			}
		}
		qs = rest
	}
	// This task requires its named GNN. General text and lexical backends
	// cannot substitute for an absent or disabled code-role expert.
	rest := qs[:0:0]
	for _, q := range qs {
		if q.Task == TaskLiteralRoleNeural {
			resp.Answers[q.ID] = unavailableNeuralAnswer(q)
		} else if requiresReasoningProof(q) {
			resp.Answers[q.ID] = unavailableReasoningAnswer(q)
		} else {
			rest = append(rest, q)
		}
	}
	qs = rest
	if len(qs) == 0 {
		resp.Backend = "experts"
		if e.Escalate != nil {
			e.Escalate.Apply(ctx, r, &resp)
		}
		resp.ElapsedMs = math.Round(float64(time.Since(start).Microseconds())/10) / 100
		return resp, nil
	}
	chunks, questionChunks, contextMissing, err := e.contextChunksContext(ctx, state, qs)
	if err != nil {
		return Response{}, err
	}
	// 1. collect unique hypotheses for all questions
	hypIdx := map[string]int{}
	var hyps []string
	var hypChunks [][]int
	addHyp := func(h string, selected []int) int {
		if i, ok := hypIdx[h]; ok {
			for _, ci := range selected {
				found := false
				for _, previous := range hypChunks[i] {
					found = found || previous == ci
				}
				if !found {
					hypChunks[i] = append(hypChunks[i], ci)
				}
			}
			return i
		}
		hypIdx[h] = len(hyps)
		hyps = append(hyps, h)
		hypChunks = append(hypChunks, append([]int(nil), selected...))
		return len(hyps) - 1
	}
	plans := make([]plan, len(qs))
	for qi, q := range qs {
		p := plan{q: q, contextMissing: contextMissing[qi]}
		switch {
		case q.Type == TypeNoul && !q.HasCrit:
			p.slots = []int{addHyp(statement(q.Instr), questionChunks[qi])}
			p.escape = []bool{false}
		default:
			for _, o := range q.Options {
				h, esc := hypothesisFor(q, o)
				if esc {
					p.slots = append(p.slots, -1)
					p.escape = append(p.escape, true)
					continue
				}
				p.slots = append(p.slots, addHyp(h, questionChunks[qi]))
				p.escape = append(p.escape, false)
			}
			if q.Task == TaskSkillRouting && e.Skills != nil {
				p.extra = make([][]int, len(q.Options))
				p.exHit = make([]string, len(q.Options))
				for i, o := range q.Options {
					if p.slots[i] < 0 {
						continue
					}
					for _, ex := range e.Skills.ExamplesOf(o.Key) {
						p.extra[i] = append(p.extra[i], addHyp(ex, questionChunks[qi]))
					}
				}
			}
		}
		plans[qi] = p
	}
	// 2. one batched, parallel pass over (chunk × hypothesis)
	nPairs := 0
	for _, selected := range hypChunks {
		nPairs += len(selected)
	}
	if e.MaxPairs > 0 && nPairs > e.MaxPairs {
		return Response{}, fmt.Errorf("inference budget exceeded: %d pairs (limit %d)", nPairs, e.MaxPairs)
	}
	pairs := make([]Pair, 0, nPairs)
	pairHyp, pairChunk := make([]int, 0, nPairs), make([]int, 0, nPairs)
	hypPairs := make([][]int, len(hyps))
	for hi, h := range hyps {
		for _, ci := range hypChunks[hi] {
			hypPairs[hi] = append(hypPairs[hi], len(pairs))
			pairHyp, pairChunk = append(pairHyp, hi), append(pairChunk, ci)
			pairs = append(pairs, Pair{chunks[ci], h})
		}
	}
	modelCalls, cacheHits := 0, 0
	var js []Judgement
	skillBackend := e.SkillBackend
	needsSkillBackend := false
	skillOnly := make([]bool, len(hyps)) // hypotheses used only by skill_routing questions
	if skillBackend != nil || e.SkillBackendLoader != nil {
		general := make([]bool, len(hyps))
		for _, p := range plans {
			needsSkillBackend = needsSkillBackend || p.q.Task == TaskSkillRouting
			idx := append(append([]int(nil), p.slots...), flatInts(p.extra)...)
			for _, h := range idx {
				if h < 0 {
					continue
				}
				if p.q.Task == TaskSkillRouting {
					skillOnly[h] = true
				} else {
					general[h] = true
				}
			}
		}
		for h := range skillOnly {
			skillOnly[h] = skillOnly[h] && !general[h]
		}
	}
	var gIdx, sIdx []int
	var gPairs, sPairs []Pair
	for i, pr := range pairs {
		if skillOnly[pairHyp[i]] {
			sIdx, sPairs = append(sIdx, i), append(sPairs, pr)
		} else {
			gIdx, gPairs = append(gIdx, i), append(gPairs, pr)
		}
	}
	if needsSkillBackend && skillBackend == nil {
		skillBackend, err = e.SkillBackendLoader.Load(ctx)
		if err != nil {
			return Response{}, fmt.Errorf("skill backend: %w", err)
		}
	}
	js = make([]Judgement, len(pairs))
	for _, part := range []struct {
		b   Backend
		idx []int
		ps  []Pair
	}{{e.Backend, gIdx, gPairs}, {skillBackend, sIdx, sPairs}} {
		if len(part.ps) == 0 {
			continue
		}
		var c0, h0 int64
		st, hasStats := part.b.(interface{ Stats() (int64, int64) })
		if hasStats {
			c0, h0 = st.Stats()
		}
		out, err := judge(ctx, part.b, part.ps)
		if err != nil {
			return Response{}, err
		}
		if len(out) != len(part.ps) {
			return Response{}, fmt.Errorf("%s: returned %d judgements for %d pairs", part.b.Name(), len(out), len(part.ps))
		}
		if hasStats {
			c1, h1 := st.Stats()
			modelCalls += int(c1 - c0)
			cacheHits += int(h1 - h0)
		} else {
			modelCalls += len(part.ps)
		}
		for k, i := range part.idx {
			js[i] = out[k]
		}
	}
	if len(sPairs) > 0 {
		resp.Backend += " + skills:" + skillBackend.Name()
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	// aggregate: any chunk may support (max entail) or refute (max contra) a hypothesis,
	// while opposing chunks or mutually inverted hypotheses cancel into neutrality.
	type agg struct {
		e, c, n float64
		best    int
	}
	aggs := make([]agg, len(hyps))
	maxEs := make([]float64, len(hyps))
	maxCs := make([]float64, len(hyps))
	bestCs := make([]float64, len(hyps))
	for hi := range hyps {
		best := 0
		if len(hypPairs[hi]) > 0 {
			best = pairChunk[hypPairs[hi][0]]
		}
		var maxE, maxC, bestC float64
		for k, pi := range hypPairs[hi] {
			ci, j := pairChunk[pi], js[pi]
			je, jc := clamp01(j.Entail), clamp01(j.Contra)
			if k == 0 || je > maxE {
				maxE, best, bestC = je, ci, jc
			}
			if jc > maxC {
				maxC = jc
			}
		}
		aggs[hi].best = best
		maxEs[hi], maxCs[hi], bestCs[hi] = maxE, maxC, bestC
	}
	if len(hyps) > 1 {
		stemOf := func(w string) string {
			return stem5(w)
		}
		stemsOf := func(s string) []string {
			var out []string
			for _, t := range lexDocOf(s).toks {
				if stop[t] || retrievalStop[t] || len([]rune(t)) < 2 {
					continue
				}
				out = append(out, stemOf(t))
			}
			return out
		}
		inverted := func(a, b []string) bool {
			if len(a) < 3 || len(a) != len(b) {
				return false
			}
			posA := make(map[string]int, len(a))
			for i, w := range a {
				posA[w] = i
			}
			posB := make(map[string]int, len(b))
			for i, w := range b {
				if _, ok := posA[w]; !ok {
					return false
				}
				posB[w] = i
			}
			for _, r := range a {
				ar, br := posA[r], posB[r]
				for _, x := range a {
					for _, y := range a {
						if x == y || x == r || y == r {
							continue
						}
						if posA[x] < ar && ar < posA[y] && posB[y] < br && br < posB[x] {
							return true
						}
					}
				}
			}
			return false
		}
		hStems := make([][]string, len(hyps))
		for hi, h := range hyps {
			hStems[hi] = stemsOf(h)
		}
		for hi := range hyps {
			for hj := hi + 1; hj < len(hyps); hj++ {
				if inverted(hStems[hi], hStems[hj]) {
					if maxEs[hj] >= minSubstantiveSupport && maxEs[hj] > maxCs[hi] {
						maxCs[hi] = maxEs[hj]
					}
					if maxEs[hi] >= minSubstantiveSupport && maxEs[hi] > maxCs[hj] {
						maxCs[hj] = maxEs[hi]
					}
				}
			}
		}
	}
	for hi := range hyps {
		maxE, maxC, bestC := maxEs[hi], maxCs[hi], bestCs[hi]
		var ae, ac float64
		switch {
		case maxE >= minSubstantiveSupport && maxC >= minSubstantiveSupport:
			cf := math.Min(maxE, maxC) / math.Max(maxE, maxC)
			scale := (1 - cf) * 0.25
			ae, ac = maxE*scale, maxC*scale
		case maxE >= minSubstantiveSupport:
			ae, ac = maxE, bestC
		default:
			ae, ac = maxE, maxC
		}
		if tot := ae + ac; tot > 1 {
			ae, ac = ae/tot, ac/tot
		}
		aggs[hi].e = ae
		aggs[hi].c = ac
		aggs[hi].n = clamp01(1 - ae - ac)
	}
	// few-shot: an option is as supported as its best view (description or a past example)
	for pi := range plans {
		p := &plans[pi]
		if p.extra != nil {
			p.primary = append([]int(nil), p.slots...)
		}
		for i, ex := range p.extra {
			for _, h := range ex {
				if aggs[h].e >= ExampleMinSupport && aggs[h].e > aggs[p.slots[i]].e {
					p.slots[i], p.exHit[i] = h, hyps[h]
				}
			}
		}
	}
	lexical := e.Backend.Name() == "lexical-fallback"
	calibrated := len(e.Calib.Fitted) > 0
	if lexical {
		resp.Warnings = append(resp.Warnings, "Neural weights not loaded: lexical fallback is used and every answer is routed to a human.")
	} else if !calibrated {
		resp.Warnings = append(resp.Warnings, "No fitted calibration loaded: route is capped at \"review\". Run `dai calibrate` on labelled data.")
	} else {
		for _, t := range []string{TypeNoul, TypeChoice, TypeScore} {
			if n := e.Calib.Fitted[t]; n < MinCalibrationN {
				if !hasType(qs, t) {
					continue
				}
				resp.Warnings = append(resp.Warnings, fmt.Sprintf("Calibration for %s fitted on %d examples (<%d): its route is capped at \"review\".", t, n, MinCalibrationN))
			}
		}
	}
	calibrationIssue := e.CalibrationIssue()
	if calibrationIssue != "" {
		resp.Warnings = append(resp.Warnings, "Calibration identity not verified ("+calibrationIssue+"): neural auto routing is disabled. Re-run calibrate for this configuration.")
	}
	doc := lexDocOf(state)
	// 3. typed answers
	for _, p := range plans {
		q := p.q
		ev := func(slot int) []string {
			if slot < 0 {
				return nil
			}
			s := chunks[aggs[slot].best]
			if len([]rune(s)) > 200 {
				s = string([]rune(s)[:200]) + "…"
			}
			return []string{s}
		}
		side := func(slot int) float64 { // signed log-odds of support, shrunk by neutrality
			a := aggs[slot]
			return (math.Log(a.e+eps) - math.Log(a.c+eps)) * (a.e + a.c)
		}
		var ans Answer
		ans.Type = q.Type
		switch q.Type {
		case TypeNoul:
			var z float64
			var evSlot int
			if !q.HasCrit {
				z, evSlot = side(p.slots[0]), p.slots[0]
			} else {
				hasT, hasF := !p.escape[0], !p.escape[1]
				zt, zf := 0.0, 0.0
				if hasT {
					zt = side(p.slots[0])
				}
				if hasF {
					zf = side(p.slots[1])
				}
				switch {
				case hasT && hasF:
					z = (zt - zf) / 1.5
				case hasT:
					z = zt
				default:
					z = -zf
				}
				evSlot = p.slots[0]
				if zf > zt && !p.escape[1] {
					evSlot = p.slots[1]
				}
				if evSlot < 0 {
					evSlot = p.slots[1]
				}
			}
			var lexEv []string
			if !e.NoLex {
				if lz, found, ok := noulVote(q, doc); ok {
					z += e.lexW(TypeNoul) * lz
					if len(found) > 0 {
						lexEv = []string{lexEvidence("вопроса", found)}
					}
				}
			}
			pv := sigmoid(z / e.Calib.temp(TypeNoul))
			pv = round4(pv)
			ans.Noul = &pv
			ans.logits = []float64{z}
			ans.Route = DefaultRoute(NoulCertainty(pv))
			ans.Evidence = append(lexEv, ev(evSlot)...)
		case TypeChoice, TypeScore:
			z := make([]float64, len(q.Options))
			var sumZ, nZ float64
			for i, s := range p.slots {
				if s < 0 {
					continue
				}
				a := aggs[s]
				z[i] = math.Log(a.e+eps) - 0.5*math.Log(a.c+eps)
				sumZ += z[i]
				nZ++
			}
			var votes []lexVote
			skillLex := !e.NoLex && q.Task == TaskSkillRouting && e.Skills != nil
			denseBest := -1
			for i, s := range p.slots {
				if s >= 0 && (denseBest < 0 || z[i] > z[denseBest]) {
					denseBest = i
				}
			}
			if skillLex {
				votes = skillVotes(e.Skills, state, q)
				for i, s := range p.slots {
					if s >= 0 {
						z[i] += SkillLexWeight * votes[i].z
					}
				}
			} else if !e.NoLex {
				votes = optionVotes(q, doc)
				sumZ = 0
				for i, s := range p.slots {
					if s >= 0 {
						z[i] += e.lexW(q.Type) * votes[i].z
						sumZ += z[i]
					}
				}
			}
			maxSupport := 0.0
			for i, slot := range p.slots {
				if slot < 0 {
					continue
				}
				support := aggs[slot].e
				if p.primary != nil {
					support = aggs[p.primary[i]].e
				}
				if skillLex && votes[i].z > 0 {
					support = math.Max(support, 1-math.Exp(-votes[i].z/SkillLexScale))
				} else if votes != nil && votes[i].z > 0 {
					support = math.Max(support, sigmoid(e.lexW(q.Type)*votes[i].z))
				}
				maxSupport = math.Max(maxSupport, support)
			}
			for i, slot := range p.slots {
				if slot < 0 {
					// An abstain/escape option (like "other") may only win when no
					// substantive option is supported; otherwise it would outrank a
					// weakly but sufficiently backed answer.
					if maxSupport >= minSubstantiveSupport {
						z[i] = math.Log(eps)
					} else {
						z[i] = math.Log(1 - maxSupport + eps)
					}
				}
			}
			temp := e.Calib.temp(q.Type)
			if q.Task == TaskSkillRouting && e.Calib.Fitted[TaskSkillRouting] > 0 {
				temp = e.Calib.temp(TaskSkillRouting)
			}
			probs := softmax(z, temp)
			ans.logits = z
			pr := make(Probs, len(probs))
			best := 0
			for i, o := range q.Options {
				pr[i] = KV{o.Key, probs[i]}
				ans.keys = append(ans.keys, o.Key)
				if probs[i] > probs[best] {
					best = i
				}
			}
			ans.Probabilities = pr
			var conf float64
			if q.Type == TypeChoice {
				ans.Choice = q.Options[best].Key
				conf = ChoiceConfidence(probs)
			} else {
				vals := levelValues(q.Options)
				ans.values = vals
				sc := 0.0
				for i, v := range vals {
					sc += probs[i] * v
				}
				sc = round4(sc)
				ans.Score = &sc
				conf = ScoreConfidence(probs)
				ans.Legend = make(map[string]string, len(q.Options))
				for _, o := range q.Options {
					ans.Legend[o.Key] = o.Text
				}
			}
			conf = round4(conf)
			ans.Confidence = &conf
			ans.Route = DefaultRoute(conf)
			if q.Type == TypeChoice && (conf < 0.1 || maxSupport < minSubstantiveSupport) {
				ans.Abstained, ans.Reason, ans.Route = true, "insufficient_support", "human"
				ans.Checks = []NextCheck{{ID: "review_context", Title: "Уточнить контекст находки", Why: "Предоставленных данных недостаточно для уверенного выбора.", Kind: "review"}}
			}
			ans.Evidence = ev(p.slots[best])
			if skillLex {
				ans.Evidence = skillEvidence(state, q, probs, votes, best)
				if p.exHit != nil && p.exHit[best] != "" {
					ans.Evidence = append(ans.Evidence, "похоже на прошлый запрос: «"+p.exHit[best]+"»")
				}
				if _, inj := SplitInjection(state); len(inj) > 0 && ans.Route == "auto" {
					ans.Route = "review" // a steered request is never routed automatically
				}
				// two-channel agreement: auto only when the neural and the lexical
				// channel independently pick the winner
				lexBest := -1
				for i := range votes {
					if p.slots[i] >= 0 && votes[i].z > 0 && (lexBest < 0 || votes[i].z > votes[lexBest].z) {
						lexBest = i
					}
				}
				if ans.Route == "auto" && len(votes[best].found) < 2 && (p.exHit == nil || p.exHit[best] == "") {
					ans.Route = "review" // one matched word is not enough evidence to act on
				}
				if ans.Route == "auto" && (denseBest != best || lexBest != best) {
					ans.Route = "review"
					ans.Evidence = append(ans.Evidence, "каналы не согласны: нейросеть за "+q.Options[max(denseBest, 0)].Key+", словарь за "+keyOr(q, lexBest))
				}
			} else if votes != nil && len(votes[best].found) > 0 {
				ans.Evidence = append([]string{lexEvidence(q.Options[best].Key, votes[best].found)}, ans.Evidence...)
			}
		}
		ans.Source = e.Backend.Name()
		if q.Task == TaskSkillRouting && skillBackend != nil {
			ans.Source = skillBackend.Name()
		}
		e.attachSkillPath(q, &ans)
		if p.contextMissing {
			ans.Abstained, ans.Reason, ans.Route = true, "no_relevant_context", "human"
			ans.Checks = append(ans.Checks, NextCheck{ID: "provide_evidence", Title: "Уточнить исходные факты", Why: "В длинном контексте не найдено фрагментов, связанных с вопросом.", Kind: "review"})
		}
		if lexical {
			ans.Route = "human"
		} else if ans.Route == "auto" && q.Task == TaskSkillRouting {
			if e.Calib.Fitted[TaskSkillRouting] < MinCalibrationN {
				ans.Route = "review"
			}
		} else if ans.Route == "auto" && e.Calib.Fitted[q.Type] < MinCalibrationN {
			ans.Route = "review" // never act automatically on uncalibrated probabilities
		}
		if calibrationIssue != "" && ans.Route == "auto" {
			ans.Route = "review"
		}
		resp.Answers[q.ID] = ans
	}
	if !e.NoPlan && e.Skills != nil {
		for _, p := range plans {
			if p.q.Task == TaskSkillRouting {
				if a, ok := resp.Answers[p.q.ID]; ok {
					a.Plan = e.skillPlan(ctx, state, p.q, a)
					resp.Answers[p.q.ID] = a
				}
			}
		}
	}
	if e.Escalate != nil {
		e.Escalate.Apply(ctx, r, &resp)
	}
	// usage
	in := e.Backend.Tokens(state)
	for _, h := range hyps {
		in += e.Backend.Tokens(h)
	}
	out := 0
	for _, a := range resp.Answers {
		out += 1 + len(a.Probabilities)
	}
	esc, cost := resp.Usage.Escalated, resp.Usage.EscalationCost
	resp.Usage = Usage{InputTokens: in, OutputTokens: out, ModelCalls: modelCalls + resp.Usage.ModelCalls, CacheHits: cacheHits, Escalated: esc, EscalationCost: cost}
	resp.ElapsedMs = math.Round(float64(time.Since(start).Microseconds())/10) / 100
	return resp, nil
}

// expandSkills fills criteria-less skill_routing questions from the
// server-side registry. Questions that already carry criteria are left alone.
func (e *Engine) expandSkills(state string, qs *[]compiled) error {
	for i, q := range *qs {
		if q.Task != TaskSkillRouting || q.HasCrit {
			continue
		}
		if e.Skills == nil {
			return fmt.Errorf("%s: skill_routing without criteria needs a server skill registry (-skills)", q.ID)
		}
		opts, err := e.Skills.ExpandFor(state)
		if err != nil {
			return fmt.Errorf("%s: %v", q.ID, err)
		}
		q.Options = opts
		q.HasCrit = true
		q.AbstainKey = SkillOtherKey
		(*qs)[i] = q
	}
	return nil
}

// attachSkillPath adds the winner's SKILL.md path to a skill_routing answer,
// so clients learn the path without scanning anything themselves.
func (e *Engine) attachSkillPath(q compiled, ans *Answer) {
	if q.Task != TaskSkillRouting || e.Skills == nil {
		return
	}
	if ans.Choice == "" || ans.Choice == SkillOtherKey {
		return
	}
	if path, ok := e.Skills.PathOf(ans.Choice); ok {
		ans.References = append(ans.References, EvidenceReference{Kind: "source", File: path})
	}
}

func levelValues(opts []Option) []float64 {
	vals := make([]float64, len(opts))
	numeric := true
	for i, o := range opts {
		v, err := strconv.ParseFloat(strings.TrimSpace(o.Key), 64)
		if err != nil {
			numeric = false
			break
		}
		vals[i] = v
	}
	if !numeric {
		for i := range vals {
			vals[i] = float64(i)
		}
	}
	return vals
}

func hasType(qs []compiled, t string) bool {
	for _, q := range qs {
		if q.Type == t {
			return true
		}
	}
	return false
}

// judge scores pairs with b, honouring cancellation when the backend supports it.
func judge(ctx context.Context, b Backend, pairs []Pair) ([]Judgement, error) {
	if cb, ok := b.(interface {
		JudgeBatchContext(context.Context, []Pair) ([]Judgement, error)
	}); ok {
		return cb.JudgeBatchContext(ctx, pairs)
	}
	return b.JudgeBatch(pairs), nil
}

func flatInts(xs [][]int) []int {
	var out []int
	for _, x := range xs {
		out = append(out, x...)
	}
	return out
}

func (e *Engine) lexW(t string) float64 {
	if v, ok := e.LexScale[t]; ok {
		return LexWeight * v
	}
	return LexWeight
}
