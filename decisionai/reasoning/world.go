// Package reasoning executes bounded, explicit facts and Horn rules. A proof
// records its sources; unsupported statements and contradictory sources are
// different outcomes, and contradictions never license arbitrary conclusions.
package reasoning

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Atom struct {
	Subject   string `json:"subject"`
	Predicate string `json:"predicate"`
	Object    string `json:"object,omitempty"`
	Time      string `json:"time,omitempty"`
	Negated   bool   `json:"negated,omitempty"`
}

type Fact struct {
	Atom
	Source string `json:"source,omitempty"`
}
type Rule struct {
	All    []Atom `json:"all"`
	Then   Atom   `json:"then"`
	Source string `json:"source,omitempty"`
	Domain string `json:"domain,omitempty"`
}
type Step struct {
	ID       int    `json:"id"`
	Claim    Atom   `json:"claim"`
	Source   string `json:"source"`
	Premises []int  `json:"premises,omitempty"`
	Builtin  bool   `json:"builtin,omitempty"`
}
type Verdict struct {
	Status string `json:"status"` // supported, refuted, unknown, conflict
	Proof  []Step `json:"proof,omitempty"`
}

// Trace contains the executed proof, not a generated rationale. Source strings
// identify input facts/rules; Premises refer to earlier steps in Proof.
type Trace struct {
	SchemaVersion int    `json:"schema_version"`
	Query         Atom   `json:"query"`
	Status        string `json:"status"`
	Proof         []Step `json:"proof,omitempty"`
	Facts         int    `json:"facts"`
	Rules         int    `json:"rules"`
	Work          int    `json:"work"`
	LimitReason   string `json:"limit_reason,omitempty"`
	Scope         string `json:"scope"`
}
type World struct {
	Steps        []Step
	Rules        []Rule
	index        map[Atom]int
	builtinRules map[int]bool
	Limited      bool
	Recognized   bool
	Missing      []string
	Work         int
	LimitReason  string
}

const (
	MaxFacts  = 512
	MaxRules  = 128
	MaxRounds = 16
)
const MaxWork = 50000

func strictOrder(predicate string) bool {
	switch predicate {
	case "taller", "older", "before", "heavier", "larger", "faster":
		return true
	}
	return false
}

func (w *World) limit(reason string) {
	w.Limited = true
	if w.LimitReason == "" {
		w.LimitReason = reason
	}
}

func New() *World { return &World{index: map[Atom]int{}, builtinRules: map[int]bool{}} }
func Entity(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
func opposite(a Atom) Atom { a.Negated = !a.Negated; return a }
func normalize(a Atom) Atom {
	a.Subject, a.Predicate, a.Object = Entity(a.Subject), strings.ToLower(strings.TrimSpace(a.Predicate)), Entity(a.Object)
	a.Time = strings.ToLower(strings.TrimSpace(a.Time))
	return a
}

func (w *World) add(a Atom, source string, premises []int) bool {
	a = normalize(a)
	if a.Subject == "" || a.Predicate == "" {
		return false
	}
	if id, ok := w.index[a]; ok {
		// A later independent proof can replace a derivation whose premises
		// became contradictory. Never discard a concrete input fact.
		if len(w.Steps[id].Premises) == 0 || w.valid(id, map[int]bool{}) {
			return false
		}
	}
	if len(w.Steps) >= MaxFacts {
		w.limit("facts_limit")
		return false
	}
	w.index[a] = len(w.Steps)
	w.Steps = append(w.Steps, Step{ID: len(w.Steps), Claim: a, Source: source, Premises: append([]int(nil), premises...)})
	w.Recognized = true
	return true
}

func (w *World) Add(a Atom, source string) { w.add(a, source, nil) }
func (w *World) AddRule(r Rule) {
	if len(w.Rules) >= MaxRules || len(r.All) == 0 || len(r.All) > 8 {
		w.limit("rules_limit")
		return
	}
	for i := range r.All {
		r.All[i] = normalize(r.All[i])
	}
	r.Then = normalize(r.Then)
	w.Rules = append(w.Rules, r)
	w.Recognized = true
}

func variable(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "$") }
func bind(pattern, value string, env map[string]string) bool {
	if !variable(pattern) {
		return pattern == value
	}
	if old, ok := env[pattern]; ok {
		return old == value
	}
	env[pattern] = value
	return true
}
func instantiate(a Atom, env map[string]string) (Atom, bool) {
	for _, slot := range []*string{&a.Subject, &a.Object, &a.Time} {
		if variable(*slot) {
			value, ok := env[*slot]
			if !ok {
				return Atom{}, false
			}
			*slot = value
		}
	}
	return a, true
}

func (w *World) Solve() {
	if w.Limited {
		return
	}
	// Only intrinsically transitive relations use closure; e.g. "gave to"
	// and "approved" cannot inherit transitivity from surface word overlap.
	preds := map[string]bool{}
	for _, step := range w.Steps {
		preds[step.Claim.Predicate] = true
	}
	for _, rule := range w.Rules {
		preds[rule.Then.Predicate] = true
	}
	for _, pred := range []string{"taller", "older", "before", "heavier", "larger", "faster", "inside"} {
		if preds[pred] {
			source := "transitivity:" + pred
			exists := false
			for i, r := range w.Rules {
				if w.builtinRules[i] && r.Then.Predicate == pred {
					exists = true
					break
				}
			}
			if !exists {
				index := len(w.Rules)
				w.AddRule(Rule{All: []Atom{{Subject: "$x", Predicate: pred, Object: "$y", Time: "$t"}, {Subject: "$y", Predicate: pred, Object: "$z", Time: "$t"}}, Then: Atom{Subject: "$x", Predicate: pred, Object: "$z", Time: "$t"}, Source: source})
				if len(w.Rules) > index {
					w.builtinRules[index] = true
				}
			}
		}
	}
	for round := 0; round < MaxRounds; round++ {
		changed := false
		for ruleIndex, rule := range w.Rules {
			transitive := w.builtinRules[ruleIndex]
			var search func(int, map[string]string, []int)
			search = func(at int, env map[string]string, proof []int) {
				if w.Limited {
					return
				}
				if at == len(rule.All) {
					head, ok := instantiate(rule.Then, env)
					if !ok {
						return
					}
					if rule.Domain != "" && !strings.HasPrefix(head.Subject, rule.Domain) {
						return
					}
					if transitive && head.Subject == head.Object {
						return
					}
					added := w.add(head, rule.Source, proof)
					if added && transitive {
						w.Steps[len(w.Steps)-1].Builtin = true
					}
					changed = added || changed
					return
				}
				pattern := rule.All[at]
				// Snapshot: rules added during this pass cannot make iteration
				// unbounded; a later round observes the newly derived facts.
				n := len(w.Steps)
				for i := 0; i < n; i++ {
					if w.Work >= MaxWork {
						w.limit("work_limit")
						return
					}
					w.Work++
					fact := w.Steps[i].Claim
					if fact.Predicate != pattern.Predicate || fact.Negated != pattern.Negated {
						continue
					}
					if w.index[fact] != i || w.contradicted(fact) || !w.valid(i, map[int]bool{}) {
						continue
					}
					next := make(map[string]string, len(env)+3)
					for k, v := range env {
						next[k] = v
					}
					if bind(pattern.Subject, fact.Subject, next) && bind(pattern.Object, fact.Object, next) && bind(pattern.Time, fact.Time, next) {
						search(at+1, next, append(append([]int(nil), proof...), i))
					}
				}
			}
			search(0, map[string]string{}, nil)
		}
		if !changed {
			return
		}
	}
	w.limit("rounds_limit")
}

func (w *World) contradicted(a Atom) bool {
	if _, ok := w.index[opposite(a)]; ok {
		return true
	}
	if !a.Negated && strictOrder(a.Predicate) {
		reverse := a
		reverse.Subject, reverse.Object = reverse.Object, reverse.Subject
		if _, ok := w.index[reverse]; ok {
			return true
		}
	}
	return false
}

func (w *World) valid(id int, visited map[int]bool) bool {
	// Visit each retained step once, even when many rules share the same
	// premises. A diamond-shaped proof must not cause exponential recursion.
	stack := []int{id}
	for len(stack) > 0 {
		at := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if at < 0 || at >= len(w.Steps) {
			return false
		}
		if visited[at] {
			continue
		}
		visited[at] = true
		for _, premise := range w.Steps[at].Premises {
			if premise < 0 || premise >= at || w.contradicted(w.Steps[premise].Claim) {
				return false
			}
			stack = append(stack, premise)
		}
	}
	return true
}
func (w *World) proof(ids ...int) []Step {
	seen := map[int]bool{}
	var visit func(int)
	visit = func(id int) {
		if seen[id] {
			return
		}
		seen[id] = true
		for _, p := range w.Steps[id].Premises {
			visit(p)
		}
	}
	for _, id := range ids {
		visit(id)
	}
	order := []int{}
	for id := range seen {
		order = append(order, id)
	}
	sort.Ints(order)
	proof := make([]Step, 0, len(order))
	for _, id := range order {
		proof = append(proof, w.Steps[id])
	}
	return proof
}

func (w *World) support(a Atom) (int, bool) {
	if id, ok := w.index[a]; ok && w.valid(id, map[int]bool{}) {
		return id, true
	}
	// B > A proves not(A > B), but not(A > B) does not prove B > A:
	// the values could be equal. Negation never invents a strict inequality.
	if a.Negated && strictOrder(a.Predicate) {
		reverse := opposite(a)
		reverse.Subject, reverse.Object = reverse.Object, reverse.Subject
		if id, ok := w.index[reverse]; ok && w.valid(id, map[int]bool{}) {
			return id, true
		}
	}
	return 0, false
}

func (w *World) Query(a Atom) Verdict {
	if w.Limited {
		return Verdict{Status: "unknown"}
	}
	a = normalize(a)
	pos, p := w.support(a)
	neg, n := w.support(opposite(a))
	switch {
	case p && n:
		return Verdict{Status: "conflict", Proof: w.proof(pos, neg)}
	case p:
		return Verdict{Status: "supported", Proof: w.proof(pos)}
	case n:
		return Verdict{Status: "refuted", Proof: w.proof(neg)}
	default:
		return Verdict{Status: "unknown"}
	}
}

func (w *World) Explain(a Atom) *Trace {
	v := w.Query(a)
	return &Trace{SchemaVersion: 1, Query: normalize(a), Status: v.Status,
		Proof: v.Proof, Facts: len(w.Steps), Rules: len(w.Rules), Work: w.Work,
		LimitReason: w.LimitReason, Scope: "explicit_facts_and_rules"}
}

func (w *World) FromJSON(state any) (bool, error) {
	obj, ok := state.(map[string]any)
	if !ok {
		return false, nil
	}
	if current, exists := obj["current"]; exists {
		obj, ok = current.(map[string]any)
		if !ok {
			return false, nil
		}
	}
	_, facts := obj["facts"]
	_, rules := obj["rules"]
	if !facts && !rules {
		return false, nil
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return true, err
	}
	var doc struct {
		Facts []Fact `json:"facts"`
		Rules []Rule `json:"rules"`
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		return true, err
	}
	if len(doc.Facts) > MaxFacts || len(doc.Rules) > MaxRules {
		return true, fmt.Errorf("reasoning budget exceeded")
	}
	for i, fact := range doc.Facts {
		if strings.TrimSpace(fact.Subject) == "" || strings.TrimSpace(fact.Predicate) == "" || variable(fact.Subject) || variable(fact.Object) || variable(fact.Time) || variable(fact.Predicate) {
			return true, fmt.Errorf("fact %d needs concrete subject/predicate", i)
		}
		source := fact.Source
		if source == "" {
			source = fmt.Sprintf("facts[%d]", i)
		}
		w.Add(fact.Atom, source)
	}
	for i, rule := range doc.Rules {
		if rule.Source == "" {
			rule.Source = fmt.Sprintf("rules[%d]", i)
		}
		if strings.TrimSpace(rule.Then.Subject) == "" || strings.TrimSpace(rule.Then.Predicate) == "" || len(rule.All) == 0 || len(rule.All) > 8 || variable(rule.Then.Predicate) {
			return true, fmt.Errorf("rule %d is incomplete", i)
		}
		bound := map[string]bool{}
		for _, premise := range rule.All {
			if strings.TrimSpace(premise.Subject) == "" || strings.TrimSpace(premise.Predicate) == "" || variable(premise.Predicate) {
				return true, fmt.Errorf("rule %d has an incomplete premise", i)
			}
			for _, value := range []string{premise.Subject, premise.Object, premise.Time} {
				if variable(value) {
					bound[Entity(value)] = true
				}
			}
		}
		for _, value := range []string{rule.Then.Subject, rule.Then.Object, rule.Then.Time} {
			if variable(value) && !bound[Entity(value)] {
				return true, fmt.Errorf("rule %d has an unbound conclusion", i)
			}
		}
		w.AddRule(rule)
	}
	return true, nil
}
