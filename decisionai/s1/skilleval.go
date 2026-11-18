package s1

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
)

// SkillCase is one routing test: a request and the skills that count as
// correct ("other" means no skill should be picked).
type SkillCase struct {
	Group  string   `json:"group"`
	State  string   `json:"state"`
	Accept []string `json:"accept"`
	// Plan, when set, is the set of skills a multi-step request needs.
	Plan []string `json:"plan,omitempty"`
}

// SkillEvalReport summarises skill routing quality on a case set.
type SkillEvalReport struct {
	Skills       int                `json:"skills"`
	Cases        int                `json:"cases"`
	Top1         float64            `json:"top1"`
	Top3         float64            `json:"top3"`
	OtherRecall  float64            `json:"other_recall"`  // "nothing fits" cases answered other
	FalseAbstain float64            `json:"false_abstain"` // in-scope cases answered other
	ByGroup      map[string]float64 `json:"top1_by_group"`
	PlanExact    float64            `json:"plan_exact"`      // multi-step cases with exactly the right skill set
	PlanFalse    float64            `json:"plan_false_rate"` // single-step cases that got a plan anyway
	ECE          float64            `json:"ece"`             // 10-bin calibration error of the top probability
	AutoRate     float64            `json:"auto_rate"`
	AutoAccuracy float64            `json:"auto_accuracy"`
	LatencyP50   float64            `json:"latency_ms_p50"`
	LatencyP95   float64            `json:"latency_ms_p95"`
	Failures     []string           `json:"failures,omitempty"`
}

func ReadSkillCases(r io.Reader) ([]SkillCase, error) {
	var out []SkillCase
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var c SkillCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		if c.State == "" || len(c.Accept) == 0 {
			return nil, fmt.Errorf("line %d: state and accept are required", n)
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// EvaluateSkills routes every case through the engine (which must have a
// registry) and scores top-1/top-3 against the accepted skills.
func (e *Engine) EvaluateSkills(cases []SkillCase) (SkillEvalReport, error) {
	rep := SkillEvalReport{Cases: len(cases), ByGroup: map[string]float64{}}
	if e.Skills == nil {
		return rep, fmt.Errorf("skill registry is not loaded (use -skills)")
	}
	rep.Skills = len(e.Skills.Skills)
	var top1, top3, otherN, otherOK, inN, falseAbs int
	groupN, groupOK := map[string]int{}, map[string]int{}
	var lat []float64
	var planN, planOK, singleN, planFalse, autoN, autoOK int
	var conf []float64
	var hit []bool
	for _, c := range cases {
		body, _ := json.Marshal(map[string]any{"state": c.State, "questions": map[string]any{
			"skill": map[string]any{"type": "choice", "task": TaskSkillRouting, "instructions": "Какой скил нужен?"}}})
		var rq Request
		if err := json.Unmarshal(body, &rq); err != nil {
			return rep, err
		}
		resp, err := e.Decide(rq)
		if err != nil {
			return rep, fmt.Errorf("%q: %v", c.State, err)
		}
		lat = append(lat, resp.ElapsedMs)
		a := resp.Answers["skill"]
		acc := map[string]bool{}
		for _, k := range c.Accept {
			acc[k] = true
		}
		got := a.Choice
		if a.Abstained {
			got = SkillOtherKey
		}
		ps := append(Probs(nil), a.Probabilities...)
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].P > ps[j].P })
		groupN[c.Group]++
		ok1, ok3 := acc[got], acc[got]
		if len(ps) > 0 {
			conf = append(conf, ps[0].P)
			hit = append(hit, ok1)
		}
		if a.Route == "auto" {
			autoN++
			if ok1 {
				autoOK++
			}
		}
		if len(c.Plan) > 0 {
			planN++
			want := map[string]bool{}
			for _, k := range c.Plan {
				want[k] = true
			}
			exact := len(a.Plan) == len(want)
			for _, st := range a.Plan {
				exact = exact && want[st.Skill]
			}
			if exact {
				planOK++
			} else {
				var got []string
				for _, st := range a.Plan {
					got = append(got, st.Skill)
				}
				rep.Failures = append(rep.Failures, fmt.Sprintf("[plan] %q -> %v, want %v", c.State, got, c.Plan))
			}
		} else {
			singleN++
			if len(a.Plan) > 0 {
				planFalse++
				rep.Failures = append(rep.Failures, fmt.Sprintf("[false-plan] %q -> %d steps", c.State, len(a.Plan)))
			}
		}
		if acc[SkillOtherKey] {
			otherN++
			if ok1 {
				otherOK++
			}
		} else {
			inN++
			if got == SkillOtherKey {
				falseAbs++
			}
			for i := 0; i < len(ps) && i < 3; i++ {
				ok3 = ok3 || acc[ps[i].Key]
			}
		}
		if ok1 {
			top1++
			groupOK[c.Group]++
		} else {
			var top []string
			for i := 0; i < len(ps) && i < 3; i++ {
				top = append(top, fmt.Sprintf("%s:%.2f", ps[i].Key, ps[i].P))
			}
			rep.Failures = append(rep.Failures, fmt.Sprintf("[%s] %q -> %s, want %v, top %v", c.Group, c.State, got, c.Accept, top))
		}
		if ok3 {
			top3++
		}
	}
	div := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return round4(float64(a) / float64(b))
	}
	rep.Top1, rep.Top3 = div(top1, len(cases)), div(top3, len(cases))
	rep.OtherRecall, rep.FalseAbstain = div(otherOK, otherN), div(falseAbs, inN)
	rep.PlanExact, rep.PlanFalse = div(planOK, planN), div(planFalse, singleN)
	rep.AutoRate, rep.AutoAccuracy = div(autoN, len(cases)), div(autoOK, autoN)
	rep.ECE = round4(ece(conf, hit))
	for g, n := range groupN {
		rep.ByGroup[g] = div(groupOK[g], n)
	}
	if len(lat) > 0 {
		sort.Float64s(lat)
		rep.LatencyP50, rep.LatencyP95 = lat[len(lat)/2], lat[len(lat)*95/100]
	}
	return rep, nil
}

func ece(conf []float64, hit []bool) float64 {
	if len(conf) == 0 {
		return 0
	}
	var sumC, sumA [10]float64
	var cnt [10]int
	for i, c := range conf {
		b := int(c * 10)
		if b > 9 {
			b = 9
		}
		sumC[b] += c
		if hit[i] {
			sumA[b]++
		}
		cnt[b]++
	}
	var e float64
	for b := 0; b < 10; b++ {
		if cnt[b] > 0 {
			e += math.Abs(sumC[b]-sumA[b]) / float64(len(conf))
		}
	}
	return e
}

// skillTargets routes cases and returns raw logits with accepted indices,
// the input of temperature fitting.
func (e *Engine) skillTargets(cases []SkillCase) ([][]float64, [][]bool, error) {
	var zs [][]float64
	var ok [][]bool
	sub := *e
	sub.NoPlan = true
	for _, c := range cases {
		body, _ := json.Marshal(map[string]any{"state": c.State, "questions": map[string]any{
			"s": map[string]any{"type": "choice", "task": TaskSkillRouting, "instructions": "Какой скил нужен?"}}})
		var rq Request
		if err := json.Unmarshal(body, &rq); err != nil {
			return nil, nil, err
		}
		resp, err := sub.Decide(rq)
		if err != nil {
			return nil, nil, err
		}
		a := resp.Answers["s"]
		acc := map[string]bool{}
		for _, k := range c.Accept {
			acc[k] = true
		}
		m := make([]bool, len(a.keys))
		any := false
		for i, k := range a.keys {
			m[i] = acc[k]
			any = any || m[i]
		}
		if !any || len(a.logits) != len(m) {
			continue // accepted skill was prefiltered away; nothing to fit
		}
		zs, ok = append(zs, a.logits), append(ok, m)
	}
	return zs, ok, nil
}

// FitSkillTemperature picks the softmax temperature that minimises the
// negative log of the probability mass on accepted skills.
func FitSkillTemperature(zs [][]float64, ok [][]bool) float64 {
	best, bestT := math.Inf(1), 1.0
	for t := 0.05; t <= 5; t *= 1.05 {
		var nll float64
		for i, z := range zs {
			p := softmax(z, t)
			var m float64
			for j := range p {
				if ok[i][j] {
					m += p[j]
				}
			}
			nll -= math.Log(math.Max(m, 1e-9))
		}
		if nll < best {
			best, bestT = nll, t
		}
	}
	return round4(bestT)
}

// CalibrateSkills cross-fits a skill-routing temperature: the cases are split
// in two folds, each fold is routed with only the other fold's examples
// loaded (newEngine must return a fresh engine with no examples), so no
// request is ever matched against its own example.
func CalibrateSkills(newEngine func() (*Engine, error), cases []SkillCase) (float64, int, error) {
	var zs [][]float64
	var ok [][]bool
	for fold := 0; fold < 2; fold++ {
		e, err := newEngine()
		if err != nil {
			return 0, 0, err
		}
		var test []SkillCase
		for i, c := range cases {
			if i%2 == fold {
				test = append(test, c)
			} else if len(c.Accept) == 1 && c.Accept[0] != SkillOtherKey && len(c.Plan) == 0 {
				e.Skills.addExampleNoIndex(c.Accept[0], c.State)
			}
		}
		e.Skills.reindex()
		z, k, err := e.skillTargets(test)
		if err != nil {
			return 0, 0, err
		}
		zs, ok = append(zs, z...), append(ok, k...)
	}
	return FitSkillTemperature(zs, ok), len(zs), nil
}

// ExamplesFromCases turns single-skill cases into few-shot examples.
func ExamplesFromCases(r *SkillRegistry, cases []SkillCase) int {
	n := 0
	for _, c := range cases {
		if len(c.Accept) == 1 && c.Accept[0] != SkillOtherKey && len(c.Plan) == 0 && r.addExampleNoIndex(c.Accept[0], c.State) {
			n++
		}
	}
	r.reindex()
	return n
}
