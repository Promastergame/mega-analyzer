package semai

import (
	"embed"
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	"decisionai/gnn"
)

// Events solver: "взял 3, вернул 2, взял ещё 5 — стало ли меньше?".
// Neuro-symbolic: a graph neural network reads the story as a graph (words, clauses, the asked
// entity) and says what every clause with a number does to the asked quantity
// (plus / minus / none / init). Exact arithmetic then sums the events, and the answer probability
// is computed from the GNN's per-event probabilities (distribution of the total, not a guess).

// EventClasses are the GNN output labels.
var EventClasses = []string{"plus", "minus", "none", "init"}

const (
	relNext = iota
	relPrev
	relTokClause
	relClauseTok
	relClauseNext
	relClausePrev
	relClauseStory
	relStoryClause
	EventRelations
)

// eventSplit separates story steps ("…, потом …", "…, затем …", "… и …").
var eventSplit = regexp.MustCompile(`[.;!?\n]+|,?\s+(?:а\s+|и\s+)?(?:потом|затем|после этого|позже|в конце|наконец)\s+|,\s*(?:и|а)\s+|\s+и\s+|,\s+`)

// EventClause is one story step.
type EventClause struct {
	Text   string   `json:"text"`
	Tokens []string `json:"-"`
	Amount float64  `json:"amount"`
	HasNum bool     `json:"-"`
	Effect string   `json:"effect,omitempty"`
	P      float64  `json:"p,omitempty"`
	// Unknown counts words the GNN never saw in training (their presence lowers confidence).
	Unknown int `json:"unknown_words,omitempty"`
}

// EventTarget is what the question asks about.
type EventTarget struct {
	Entity string // display word, e.g. "коробке"
	Key    string
	Role   string // preposition before it in the question: в | на | у | ""
	Item   string
	ItemK  string
}

func splitEvents(state string) []EventClause {
	var out []EventClause
	for _, c := range eventSplit.Split(normText(state), -1) {
		c = strings.TrimSpace(strings.Trim(c, ", "))
		if c == "" {
			continue
		}
		var all []string
		for _, t := range tokens(c) {
			if isWord(t) || isNumTok(t) {
				all = append(all, t)
			}
		}
		if len(all) == 0 {
			continue
		}
		var groups [][]string
		for _, part := range splitTime(all) {
			groups = append(groups, splitMultiNum(part)...)
		}
		for _, ts := range groups {
			text := c
			if len(groups) > 1 {
				text = strings.Join(ts, " ")
			}
			ec := EventClause{Text: text, Tokens: ts}
			for _, n := range FindNumbers(ts) {
				// "через 10 минут", "прошло 3 дня" — a duration, not an amount
				if n.T1 < len(ts) && timeUnits[ts[n.T1]] {
					continue
				}
				ec.HasNum, ec.Amount = true, n.Val
				break
			}
			// "купил 6 яиц и положил их в холодильник": the pronoun carries the previous amount
			if !ec.HasNum && len(out) > 0 && out[len(out)-1].HasNum {
				for _, t := range ts {
					if pronounObj[t] {
						ec.HasNum, ec.Amount = true, out[len(out)-1].Amount
						break
					}
				}
			}
			out = append(out, ec)
		}
	}
	return out
}

// splitMultiNum cuts a run-on clause with several amounts into one step per amount:
// "петя положил 20 рублей вынул 15 рублей маша вытащила 30" → 3 steps. The cut goes after
// "<number> [noun] [из/в/на … place] [обратно]", i.e. right before the next action.
func splitMultiNum(ts []string) [][]string {
	var nums []Num
	for _, n := range FindNumbers(ts) {
		if n.T1 < len(ts) && timeUnits[ts[n.T1]] {
			continue
		}
		nums = append(nums, n)
	}
	if len(nums) < 2 {
		return [][]string{ts}
	}
	var out [][]string
	start := 0
	for i, n := range nums[:len(nums)-1] {
		j := n.T1
		if j < len(ts) && isWord(ts[j]) && !movePreps[ts[j]] && !backWords[ts[j]] && !looksPastVerb(ts[j]) && !isNumWordTok(ts[j]) {
			j++ // the counted noun
		}
		for j < nums[i+1].T0 {
			if (movePreps[ts[j]] || ts[j] == "у") && j+1 < nums[i+1].T0 && !isNumWordTok(ts[j+1]) {
				if j+2 < len(ts) && stateVerbs[ts[j+2]] {
					break // "… 8 яблок | в вазе было 5": the place opens the next clause
				}
				j += 2
			} else if backWords[ts[j]] || ts[j] == "еще" || ts[j] == "назад" {
				j++
			} else {
				break
			}
		}
		if j >= nums[i+1].T0 || j <= start {
			continue // nothing between the amounts: keep together
		}
		out = append(out, ts[start:j])
		start = j
	}
	return append(out, ts[start:])
}

var stateVerbs = map[string]bool{"было": true, "были": true, "был": true, "была": true, "есть": true, "лежало": true, "лежали": true, "лежит": true, "лежат": true,
	"стояло": true, "стояли": true, "осталось": true, "остались": true, "имелось": true, "хранилось": true, "хранились": true, "жило": true, "жили": true, "росло": true, "росли": true, "плавало": true, "плавали": true}

// splitTime cuts "… съела их через час мама положила …" before a time adverbial (a new event).
func splitTime(ts []string) [][]string {
	var out [][]string
	start := 0
	for i := 1; i+1 < len(ts); i++ {
		if ts[i] != "через" && ts[i] != "спустя" {
			continue
		}
		u := i + 1
		if isNumWordTok(ts[u]) && u+1 < len(ts) {
			u++
		}
		if timeUnits[ts[u]] && i > start {
			out = append(out, ts[start:i])
			start = i
		}
	}
	return append(out, ts[start:])
}

// looksPastVerb: Russian past-tense forms end in -л/-ла/-ли/-ло ("вынул", "вытащила").
func looksPastVerb(w string) bool {
	return strings.HasSuffix(w, "л") || strings.HasSuffix(w, "ла") || strings.HasSuffix(w, "ли") || strings.HasSuffix(w, "ло")
}

var timeUnits = map[string]bool{"секунд": true, "секунды": true, "секунду": true, "минут": true, "минуты": true, "минуту": true,
	"час": true, "часа": true, "часов": true, "день": true, "дня": true, "дней": true, "недели": true, "неделю": true, "недель": true,
	"месяц": true, "месяца": true, "месяцев": true, "год": true, "года": true, "лет": true, "раз": true, "раза": true}

var pronounObj = map[string]bool{"их": true, "его": true, "ее": true}

var targetPreps = map[string]bool{"в": true, "во": true, "на": true, "у": true}

// eventTarget finds the asked entity ("в коробке", "у Пети") and item ("конфет") in the question.
func eventTarget(question string, clauses []EventClause) EventTarget {
	qt := tokens(question)
	stateKeys := map[string]bool{}
	for _, c := range clauses {
		for _, t := range c.Tokens {
			if isWord(t) {
				stateKeys[key(t)] = true
			}
		}
	}
	var tg EventTarget
	for i := 0; i+1 < len(qt); i++ {
		if targetPreps[qt[i]] && isWord(qt[i+1]) && !questionWords[qt[i+1]] && !stopWords[qt[i+1]] {
			tg.Entity, tg.Key, tg.Role = qt[i+1], key(qt[i+1]), qt[i]
			if tg.Role == "во" {
				tg.Role = "в"
			}
			break
		}
	}
	for _, t := range qt {
		k := key(t)
		if isWord(t) && len([]rune(t)) > 3 && !stopWords[t] && k != tg.Key && stateKeys[k] && !questionWords[t] {
			tg.Item, tg.ItemK = t, k
			break
		}
	}
	return tg
}

var questionWords = map[string]bool{"стало": true, "станет": true, "было": true, "осталось": true, "сколько": true, "меньше": true, "больше": true,
	"вначале": true, "сначала": true, "изначально": true, "теперь": true, "сейчас": true, "количество": true, "правда": true, "изменилось": true}

// EventGraph turns a story + question into a GNN graph; targets are clauses that carry a number.
func EventGraph(clauses []EventClause, tg EventTarget) *gnn.Graph {
	g := &gnn.Graph{}
	add := func(f []string) int {
		g.Feats = append(g.Feats, f)
		return len(g.Feats) - 1
	}
	inStory := false
	for _, c := range clauses {
		for _, t := range c.Tokens {
			if tg.Key != "" && isWord(t) && key(t) == tg.Key {
				inStory = true
			}
		}
	}
	story := add([]string{"STORY", "tgtrole:" + tg.Role, "hasitem:" + fmt.Sprint(tg.ItemK != ""), "tgtinstory:" + fmt.Sprint(inStory)})
	prevClause, prevTok := -1, -1
	for ci, c := range clauses {
		cf := []string{"CLAUSE"}
		if ci == 0 {
			cf = append(cf, "first")
		}
		if c.HasNum {
			cf = append(cf, "hasnum")
		}
		cf = append(cf, clauseFeats(c, tg)...)
		cn := add(cf)
		g.Edges = append(g.Edges, gnn.Edge{Src: cn, Dst: story, Type: relClauseStory}, gnn.Edge{Src: story, Dst: cn, Type: relStoryClause})
		if prevClause >= 0 {
			g.Edges = append(g.Edges, gnn.Edge{Src: prevClause, Dst: cn, Type: relClauseNext}, gnn.Edge{Src: cn, Dst: prevClause, Type: relClausePrev})
		}
		prevClause = cn
		prevTok = -1
		for _, t := range c.Tokens {
			f := tokenFeats(t)
			if isWord(t) {
				k := key(t)
				if tg.Key != "" && k == tg.Key {
					f = append(f, "TGT")
				}
				if tg.ItemK != "" && k == tg.ItemK {
					f = append(f, "ITEM")
				}
			}
			tn := add(f)
			g.Edges = append(g.Edges, gnn.Edge{Src: tn, Dst: cn, Type: relTokClause}, gnn.Edge{Src: cn, Dst: tn, Type: relClauseTok})
			if prevTok >= 0 {
				g.Edges = append(g.Edges, gnn.Edge{Src: prevTok, Dst: tn, Type: relNext}, gnn.Edge{Src: tn, Dst: prevTok, Type: relPrev})
			}
			prevTok = tn
		}
		if c.HasNum {
			g.Targets = append(g.Targets, cn)
		}
	}
	return g
}

func tokenFeats(t string) []string {
	if isNumTok(t) {
		return []string{"NUM"}
	}
	if _, ok := parseWordNum([]string{t}, 0); ok {
		return []string{"NUM", "w:" + t}
	}
	f := []string{"w:" + t, "s:" + stem(t)}
	r := []rune("^" + t + "$")
	for i := 0; i+3 <= len(r); i++ {
		f = append(f, "c:"+string(r[i:i+3]))
	}
	if len(r) > 5 {
		f = append(f, "pre:"+string(r[1:4]), "suf:"+string(r[len(r)-3:]))
	}
	return f
}

//go:embed eventgnn*.json
var eventModelFS embed.FS

var (
	eventModelOnce sync.Once
	eventModel     *gnn.Model
	// eventEnsemble: extra seeds shipped as eventgnn-e*.json; their probabilities are averaged
	// with the main model (one seed alone swings ±2 human answers; the average does not).
	eventEnsemble []*gnn.Model
	eventShipped  *gnn.Model
)

// EventModel returns the bundled event GNN (nil if not trained/bundled).
func EventModel() *gnn.Model {
	eventModelOnce.Do(func() {
		if b, err := eventModelFS.ReadFile("eventgnn.json"); err == nil {
			if m, err := gnn.Load(b); err == nil && len(m.Emb) > 0 {
				eventModel, eventShipped = m, m
			}
		}
		names, _ := fs.Glob(eventModelFS, "eventgnn-e*.json")
		for _, n := range names {
			b, _ := eventModelFS.ReadFile(n)
			if m, err := gnn.Load(b); err == nil && len(m.Emb) > 0 {
				eventEnsemble = append(eventEnsemble, m)
			}
		}
	})
	return eventModel
}

// predictEvents averages the shipped ensemble (or uses m alone if it was swapped in for an experiment).
func predictEvents(m *gnn.Model, g *gnn.Graph) [][]float64 {
	out := m.Predict(g)
	if m != eventShipped || len(eventEnsemble) == 0 {
		return out
	}
	for _, e := range eventEnsemble {
		for t, p := range e.Predict(g) {
			for j := range p {
				out[t][j] += p[j]
			}
		}
	}
	n := float64(len(eventEnsemble) + 1)
	for t := range out {
		for j := range out[t] {
			out[t][j] /= n
		}
	}
	return out
}

type eventQuestion struct {
	kind string // less | more | same | changed | count | diff
}

func parseEventQuestion(q string) *eventQuestion {
	s := " " + strings.Join(tokens(q), " ") + " "
	has := func(xs ...string) bool {
		for _, x := range xs {
			if strings.Contains(s, " "+x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("на сколько"):
		return &eventQuestion{"diff"}
	case has("столько же", "не изменил", "прежнее", "тоже самое", "то же самое", "так же"):
		return &eventQuestion{"same"}
	case has("сколько"):
		return &eventQuestion{"count"}
	case has("изменил", "поменял"):
		return &eventQuestion{"changed"}
	case has("меньше", "уменьшил", "убавил"):
		return &eventQuestion{"less"}
	case has("больше", "увеличил", "прибавил", "прибыло"):
		return &eventQuestion{"more"}
	}
	return nil
}

// SolveEvents answers questions about how a quantity changed over a story. nil = not this kind.
func SolveEvents(state, question string) *FactAnswer {
	m := EventModel()
	if m == nil || strings.TrimSpace(state) == "" {
		return nil
	}
	eq := parseEventQuestion(question)
	if eq == nil {
		return nil
	}
	clauses, post := takePostOps(splitEvents(state), question)
	nEv := 0
	for _, c := range clauses {
		if c.HasNum {
			nEv++
		}
	}
	if nEv == 0 || nEv > 14 {
		return nil
	}
	tg := eventTarget(question, clauses)
	g := EventGraph(clauses, tg)
	probs := predictEvents(m, g)
	voc := modelVocab(m)
	// distribution of (init known?, init value, delta) — init is "the start value", delta the change.
	type st struct {
		delta, init float64
		hasInit     bool
	}
	// dist: the GNN's own step probabilities (decides the answer); sdist: the same after the
	// out-of-vocabulary caution (decides how sure we say we are).
	dist, sdist := map[st]float64{{}: 1}, map[st]float64{{}: 1}
	update := func(d map[st]float64, c *EventClause, p []float64) map[st]float64 {
		nd := map[st]float64{}
		for s, ps := range d {
			for j, pj := range p {
				if pj < 1e-4 {
					continue
				}
				n := s
				switch EventClasses[j] {
				case "plus":
					n.delta += c.Amount
				case "minus":
					n.delta -= c.Amount
				case "init":
					n.init, n.hasInit = c.Amount, true
				}
				nd[n] += ps * pj
			}
		}
		return nd
	}
	k := 0
	var steps []string
	for i := range clauses {
		c := &clauses[i]
		if !c.HasNum {
			continue
		}
		raw := probs[k]
		p, unk := oovSoften(m, voc, *c, raw)
		k++
		c.Unknown = unk
		best := 0
		for j := range raw {
			if raw[j] > raw[best] {
				best = j
			}
		}
		c.Effect, c.P = EventClasses[best], p[best]
		dist, sdist = update(dist, c, raw), update(sdist, c, p)
		sign := map[string]string{"plus": "+", "minus": "−", "none": "не меняет", "init": "было"}[c.Effect]
		steps = append(steps, fmt.Sprintf("«%s» → %s %s (%.0f%%)", c.Text, sign, trimNum(c.Amount), 100*c.P))
	}
	// most likely scenario
	var top st
	topP := -1.0
	for s, p := range dist {
		if p > topP {
			top, topP = s, p
		}
	}
	what := tg.Entity
	if what == "" {
		what = "у героя"
	} else if tg.Role == "у" {
		what = "у " + what
	} else {
		what = tg.Role + " " + what
	}
	reason := []string{"Граф-нейросеть (GNN) разобрала шаги: " + strings.Join(steps, "; ")}
	tot := fmt.Sprintf("Итог изменения %s: %s", what, signed(top.delta))
	if top.hasInit {
		tot += fmt.Sprintf(" (было %s, стало %s)", trimNum(top.init), trimNum(top.init+top.delta))
	}
	reason = append(reason, tot)
	ans := &FactAnswer{Solver: "events-gnn", Reasoning: reason, Total: &EventTotal{Delta: top.delta, Target: strings.TrimSpace(what), Item: tg.Item, ScenarioP: math.Round(topP*1000) / 1000}}
	if top.hasInit {
		a, b := top.init, top.init+top.delta
		ans.Total.Start, ans.Total.End = &a, &b
	}
	ans.Total.Others = otherTotals(m, clauses, tg)
	for _, c := range clauses {
		if c.HasNum {
			c.P = math.Round(c.P*1000) / 1000
			ans.Steps = append(ans.Steps, c)
		}
	}
	if hasThan(question) {
		if parts := sumTargets(question, clauses, tg); len(parts) == 2 {
			return compareAnswer(m, clauses, parts, ans, eq.kind, post)
		}
	}
	if hasThan(question) {
		if parts := sumTargets(question, clauses, tg); len(parts) == 2 {
			return compareAnswer(m, clauses, parts, ans, eq.kind, post)
		}
	}
	if eq.kind == "count" {
		// «сколько в коробке и в вазе», «сколько всего конфет» — сумма по нескольким местам
		if parts := sumTargets(question, clauses, tg); len(parts) >= 2 {
			return sumAnswer(m, clauses, parts, ans, post)
		}
	}
	yes := 0.0
	switch eq.kind {
	case "less", "more", "same", "changed":
		for s, p := range dist {
			ok := false
			switch eq.kind {
			case "less":
				ok = s.delta < 0
			case "more":
				ok = s.delta > 0
			case "same":
				ok = s.delta == 0
			case "changed":
				ok = s.delta != 0
			}
			if ok {
				yes += p
			}
		}
		ans.Answer = "yes"
		if yes < 0.5 {
			ans.Answer = "no"
		}
		ans.Confidence = 0.0
		for s, p := range sdist {
			if eventHolds(eq.kind, s.delta) == (ans.Answer == "yes") {
				ans.Confidence += p
			}
		}
		ans.Confidence = math.Max(ans.Confidence, 0.5)
	case "count", "diff":
		vals := map[float64]float64{}
		for s, p := range dist {
			if eq.kind == "count" {
				if !s.hasInit {
					continue
				}
				vals[s.init+s.delta] += p
			} else {
				vals[math.Abs(s.delta)] += p
			}
		}
		noInit := 0.0
		for s, p := range dist {
			if !s.hasInit {
				noInit += p
			}
		}
		if len(vals) == 0 || (eq.kind == "count" && noInit > 0.5) {
			ans.Answer = "unknown"
			// sure it is unknown exactly as much as we are sure no step gave the start value
			ans.Confidence = 0
			for s, p := range sdist {
				if !s.hasInit {
					ans.Confidence += p
				}
			}
			ans.Confidence = math.Round(ans.Confidence*1000) / 1000
			ans.Reasoning = append(ans.Reasoning, "Сколько было вначале — в условии не сказано, поэтому точное число назвать нельзя (можно только изменение: "+signed(top.delta)+").")
			return ans
		}
		var ks []float64
		for v := range vals {
			ks = append(ks, v)
		}
		sort.Slice(ks, func(i, j int) bool { return vals[ks[i]] > vals[ks[j]] })
		ans.Answer = trimNum(applyPost(ks[0], post, &ans.Reasoning))
		ans.Confidence = 0
		for s, p := range sdist {
			if (eq.kind == "count" && s.hasInit && s.init+s.delta == ks[0]) || (eq.kind == "diff" && math.Abs(s.delta) == ks[0]) {
				ans.Confidence += p
			}
		}
		ans.Who = []string{ans.Answer}
	}
	ans.Confidence = math.Round(ans.Confidence*1000) / 1000
	return ans
}

// EventVocab collects word features of training graphs (stored in the model for OOV caution).
func EventVocab(gs []*gnn.Graph) []string {
	seen := map[string]bool{}
	for _, g := range gs {
		for _, f := range g.Feats {
			for _, x := range f {
				if strings.HasPrefix(x, "w:") {
					seen[x[2:]] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// oovSoften: every content word the GNN never saw in training makes it less sure about the
// clause — probabilities are flattened with temperature 1+OOVTemp·unknown (cap 4). 2.5 was picked
// on unseen-verb synthetic stories (answer ECE 0.075 → 0.018 at equal accuracy).
var OOVTemp = 2.5

func oovSoften(m *gnn.Model, vocab map[string]bool, c EventClause, p []float64) ([]float64, int) {
	if len(vocab) == 0 || OOVTemp == 0 {
		return p, 0
	}
	u := 0
	for _, t := range c.Tokens {
		if isWord(t) && !isNumWordTok(t) && len([]rune(t)) > 2 && !vocab[t] {
			u++
		}
	}
	if u == 0 {
		return p, 0
	}
	T := math.Min(1+OOVTemp*float64(u), 4)
	out := make([]float64, len(p))
	s := 0.0
	for i, x := range p {
		out[i] = math.Pow(math.Max(x, 1e-12), 1/T)
		s += out[i]
	}
	for i := range out {
		out[i] /= s
	}
	return out, u
}

var (
	vocabSet map[string]bool
	vocabFor *gnn.Model
)

func modelVocab(m *gnn.Model) map[string]bool {
	if vocabFor != m {
		vocabSet, vocabFor = map[string]bool{}, m
		for _, w := range m.Vocab {
			vocabSet[w] = true
		}
	}
	return vocabSet
}

func eventHolds(kind string, delta float64) bool {
	switch kind {
	case "less":
		return delta < 0
	case "more":
		return delta > 0
	case "same":
		return delta == 0
	case "changed":
		return delta != 0
	}
	return false
}

func trimNum(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%d", int64(v))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", v), "0"), ".")
}

func signed(v float64) string {
	switch {
	case v > 0:
		return "+" + trimNum(v)
	case v < 0:
		return "−" + trimNum(-v)
	}
	return "0 (не изменилось)"
}

// SetEventModel replaces the bundled model (training/evaluation).
func SetEventModel(m *gnn.Model) {
	EventModel()
	eventModel = m
}

var movePreps = map[string]bool{"из": true, "с": true, "со": true, "в": true, "во": true, "на": true}
var backWords = map[string]bool{"обратно": true, "назад": true, "место": true}

// clauseFeats summarise a clause for its node: does the counted noun match the asked item,
// does a place phrase name the asked entity or another one, is it "обратно"/ellipsis.
func clauseFeats(c EventClause, tg EventTarget) []string {
	var f []string
	ts := c.Tokens
	for i, t := range ts {
		if (isNumTok(t) || isNumWordTok(t)) && i+1 < len(ts) && isWord(ts[i+1]) && !isNumWordTok(ts[i+1]) && !movePreps[ts[i+1]] && !backWords[ts[i+1]] {
			if tg.ItemK != "" && key(ts[i+1]) == tg.ItemK {
				f = append(f, "cl:item")
			} else if tg.ItemK != "" {
				f = append(f, "cl:otheritem")
			}
		}
		if movePreps[t] && i+1 < len(ts) && isWord(ts[i+1]) && !isNumWordTok(ts[i+1]) {
			kind := "other"
			if tg.Key != "" && key(ts[i+1]) == tg.Key {
				kind = "tgt"
			}
			f = append(f, "cl:"+t+":"+kind, "cl:place:"+kind)
		}
		if backWords[t] {
			f = append(f, "cl:back")
		}
		if tg.Key != "" && isWord(t) && key(t) == tg.Key {
			f = append(f, "cl:mentions_tgt")
		}
	}
	if len(ts) > 0 {
		f = append(f, "cl:first:"+ts[0])
		if ts[0] == "еще" && len(ts) <= 3 {
			f = append(f, "cl:ellipsis")
		}
	}
	return f
}

func isNumWordTok(t string) bool {
	if isNumTok(t) {
		return true
	}
	_, ok := parseWordNum([]string{t}, 0)
	return ok
}

// otherTotals runs the GNN once more for every other place/person the story names, so the
// answer also shows "в вазе: было 5 → стало 3" next to the asked one (most likely scenario).
func otherTotals(m *gnn.Model, clauses []EventClause, tg EventTarget) []EventTotal {
	roles := map[string]string{"в": "в", "во": "в", "из": "в", "на": "на", "с": "на", "со": "на", "у": "у"}
	seen := map[string]bool{tg.Key: true, tg.ItemK: true}
	var out []EventTotal
	for _, c := range clauses {
		for i := 0; i+1 < len(c.Tokens) && len(out) < 3; i++ {
			role, ok := roles[c.Tokens[i]]
			w := c.Tokens[i+1]
			if !ok || !isWord(w) || isNumWordTok(w) || len([]rune(w)) < 3 || stopWords[w] || pronounObj[w] || questionWords[w] || seen[key(w)] {
				continue
			}
			seen[key(w)] = true
			t2 := EventTarget{Entity: w, Key: key(w), Role: role, Item: tg.Item, ItemK: tg.ItemK}
			probs := predictEvents(m, EventGraph(clauses, t2))
			et := EventTotal{Target: c.Tokens[i] + " " + w, Item: tg.Item, ScenarioP: 1}
			var start float64
			has, k := false, 0
			for _, cl := range clauses {
				if !cl.HasNum {
					continue
				}
				p := probs[k]
				k++
				best := 0
				for j := range p {
					if p[j] > p[best] {
						best = j
					}
				}
				et.ScenarioP *= p[best]
				switch EventClasses[best] {
				case "plus":
					et.Delta += cl.Amount
				case "minus":
					et.Delta -= cl.Amount
				case "init":
					start, has = cl.Amount, true
				}
			}
			if !has && et.Delta == 0 {
				continue // the story says nothing countable about it
			}
			if has {
				a, b := start, start+et.Delta
				et.Start, et.End = &a, &b
			}
			et.ScenarioP = math.Round(et.ScenarioP*1000) / 1000
			out = append(out, et)
		}
	}
	return out
}

// sumWords mark a question about everything at once: «сколько всего конфет?».
var sumWords = []string{"всего", "вместе", "в сумме", "итого", "в общей сложности", "суммарно"}

// notPlace are words that follow a preposition in a question but are not places.
var notPlace = map[string]bool{"сумме": true, "общей": true, "общем": true, "итоге": true, "конце": true}

// sumTargets returns the places a count question asks about together:
// «в коробке и (в) вазе» → [коробке, вазе]; «сколько всего конфет?» (no place named) → every
// container of the story. nil = an ordinary one-place question.
func sumTargets(question string, clauses []EventClause, tg EventTarget) []EventTarget {
	qt := tokens(question)
	stateKeys := map[string]bool{}
	for _, c := range clauses {
		for _, t := range c.Tokens {
			if isWord(t) {
				stateKeys[key(t)] = true
			}
		}
	}
	var out []EventTarget
	seen := map[string]bool{}
	add := func(w, role string) {
		k := key(w)
		if seen[k] || (tg.ItemK != "" && k == tg.ItemK) {
			return
		}
		seen[k] = true
		if role == "во" {
			role = "в"
		}
		out = append(out, EventTarget{Entity: w, Key: k, Role: role, Item: tg.Item, ItemK: tg.ItemK})
	}
	last, role := -10, ""
	for i := 0; i+1 < len(qt); i++ {
		w := qt[i+1]
		if !isWord(w) || questionWords[w] || stopWords[w] || notPlace[w] || isNumWordTok(w) {
			continue
		}
		if targetPreps[qt[i]] {
			role = qt[i]
			add(w, role)
			last = i + 1
		} else if qt[i] == "и" && last == i-1 && stateKeys[key(w)] {
			add(w, role)
			last = i + 1
		}
	}
	if len(out) >= 2 {
		return out
	}
	if len(out) > 0 {
		return nil
	}
	s := " " + strings.Join(qt, " ") + " "
	whole := false
	for _, x := range sumWords {
		if strings.Contains(s, " "+x+" ") {
			whole = true
		}
	}
	if !whole {
		return nil
	}
	roles := map[string]string{"в": "в", "во": "в", "из": "в", "на": "на", "с": "на", "со": "на"}
	for _, c := range clauses {
		for i := 0; i+1 < len(c.Tokens); i++ {
			r, ok := roles[c.Tokens[i]]
			w := c.Tokens[i+1]
			if !ok || !isWord(w) || isNumWordTok(w) || len([]rune(w)) < 3 || stopWords[w] || pronounObj[w] || questionWords[w] || notPlace[w] {
				continue
			}
			add(w, r)
		}
	}
	if len(out) < 2 || len(out) > 5 {
		return nil
	}
	return out
}

// entityTotal is the most likely start/end of one place according to the GNN.
func entityTotal(m *gnn.Model, clauses []EventClause, t EventTarget) (EventTotal, bool) {
	probs := predictEvents(m, EventGraph(clauses, t))
	et := EventTotal{Target: strings.TrimSpace(t.Role + " " + t.Entity), Item: t.Item, ScenarioP: 1}
	var start float64
	has, k := false, 0
	for _, cl := range clauses {
		if !cl.HasNum {
			continue
		}
		p := probs[k]
		k++
		best := 0
		for j := range p {
			if p[j] > p[best] {
				best = j
			}
		}
		et.ScenarioP *= p[best]
		switch EventClasses[best] {
		case "plus":
			et.Delta += cl.Amount
		case "minus":
			et.Delta -= cl.Amount
		case "init":
			start, has = cl.Amount, true
		}
	}
	if has {
		a, b := start, start+et.Delta
		et.Start, et.End = &a, &b
	}
	et.ScenarioP = math.Round(et.ScenarioP*1000) / 1000
	return et, has
}

// sumAnswer answers «сколько в A и в B / сколько всего» as the sum of every place's end value.
func sumAnswer(m *gnn.Model, clauses []EventClause, parts []EventTarget, ans *FactAnswer, post []postOp) *FactAnswer {
	var terms []string
	var tots []EventTotal
	sum, conf := 0.0, 1.0
	for _, t := range parts {
		et, ok := entityTotal(m, clauses, t)
		if !ok {
			ans.Answer = "unknown"
			ans.Confidence = 0.5
			ans.Reasoning = append(ans.Reasoning, "Сколько было вначале "+et.Target+" — в условии не сказано, поэтому общее количество назвать нельзя.")
			return ans
		}
		sum += *et.End
		conf *= et.ScenarioP
		terms = append(terms, trimNum(*et.End)+" ("+et.Target+")")
		tots = append(tots, et)
	}
	first := tots[0]
	first.Others = tots[1:]
	ans.Total = &first
	ans.Reasoning = append(ans.Reasoning, "Вопрос про несколько мест сразу — складываем: "+strings.Join(terms, " + ")+" = "+trimNum(sum))
	ans.Answer = trimNum(applyPost(sum, post, &ans.Reasoning))
	ans.Who = []string{ans.Answer}
	ans.Confidence = math.Round(conf*1000) / 1000
	return ans
}
