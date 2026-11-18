package experts

import (
	"encoding/json"
	"math"
	"testing"

	"decisionai/s1"
	"decisionai/smalirole"
)

func permutations(options []s1.Option, visit func([]s1.Option)) {
	var walk func(int)
	walk = func(i int) {
		if i == len(options) {
			visit(options)
			return
		}
		for j := i; j < len(options); j++ {
			options[i], options[j] = options[j], options[i]
			walk(i + 1)
			options[i], options[j] = options[j], options[i]
		}
	}
	walk(0)
}

func TestLiteralRoleCanonicalPermutation(t *testing.T) {
	options := []s1.Option{
		{Key: "boolean", Text: "Boolean flag bit mask; unknown when no evidence"},
		{Key: "flag_bit", Text: "Boolean flag bit mask; unknown when no evidence"},
		{Key: "bitmask", Text: "Boolean flag bit mask; unknown when no evidence"},
		{Key: "unknown", Text: "None of the declared roles"},
	}
	permutations(options, func(opts []s1.Option) {
		m, escape, used := mapLabels(opts)
		if escape < 0 || opts[escape].Key != "unknown" || used != 3 {
			t.Errorf("bad escape/count for %v: %v, %d, %d", opts, m, escape, used)
			return
		}
		for _, role := range []string{"boolean", "flag_bit", "bitmask"} {
			i, ok := m[role]
			if !ok || opts[i].Key != role {
				t.Errorf("%s mapped to %v in %v", role, m, opts)
			}
		}
	})
}

func TestLiteralRoleCanonicalLabelsDoNotAbsorbOtherRoles(t *testing.T) {
	opts := []s1.Option{{Key: "boolean", Text: "Boolean flag bit mask duration limit"}, {Key: "flag_bit", Text: "Bit mask"}, {Key: "unknown"}}
	m, escape, _ := mapLabels(opts)
	if escape != 2 {
		t.Fatal("unknown key lost")
	}
	for _, role := range []string{"bitmask", "duration_ms", "limit_threshold"} {
		if i, ok := m[role]; ok {
			t.Errorf("missing role %s was assigned to reserved key %s", role, opts[i].Key)
		}
	}
}

func TestLiteralRoleAliasesAndAmbiguousDescriptions(t *testing.T) {
	opts := []s1.Option{{Key: "limit", Text: "Unknown value"}, {Key: "delay", Text: "No descriptive hint"}, {Key: "other"}}
	m, escape, _ := mapLabels(opts)
	if m["limit_threshold"] != 0 || m["duration_ms"] != 1 || escape != 2 {
		t.Fatalf("legacy aliases broken: %v, escape=%d", m, escape)
	}
	opts = []s1.Option{{Key: "a", Text: "Delay"}, {Key: "b", Text: "Timer"}, {Key: "limit_threshold"}, {Key: "unknown"}}
	permutations(opts, func(opts []s1.Option) {
		m, _, _ := mapLabels(opts)
		if _, ok := m["duration_ms"]; ok {
			t.Errorf("ambiguous duration chose a variant by position: %v", m)
		}
	})
	opts = []s1.Option{{Key: "limit"}, {Key: "limit_threshold", Text: "A timer or unknown value"}, {Key: "duration_ms"}, {Key: "unknown"}}
	m, _, _ = mapLabels(opts)
	if m["limit_threshold"] != 1 {
		t.Fatal("alias won over canonical key")
	}
}

func TestLiteralRoleExplicitTaskDispatch(t *testing.T) {
	r := Role{Model: &smalirole.Model{}}
	state := map[string]any{"candidate": "getMaxCoins() const/16 v0, 0x64"}
	q := s1.ExpertQuestion{Type: s1.TypeChoice, Task: s1.TaskLiteralRole, Instr: "Classify this.", Options: []s1.Option{{Key: "limit_threshold"}, {Key: "duration_ms"}, {Key: "unknown"}}}
	if _, handled := r.Answer(state, "", q); !handled {
		t.Error("explicit literal_role was ignored because display text lacked a keyword")
	}
	q.Task, q.Instr = s1.TaskSkillRouting, "Classify the literal role"
	if _, handled := r.Answer(state, "", q); handled {
		t.Error("literal expert intercepted another explicit task")
	}
}

func TestLiteralRoleModelDistributionKeepsCanonicalKeys(t *testing.T) {
	e := engine(t)
	r := Role{Model: roleModel(e)}
	if r.Model == nil {
		t.Skip("no Smali model")
	}
	code := ".method public static configure(Landroid/view/View;)V\n    .locals 1\n    const/4 v0, 0x1\n    invoke-virtual {p0, v0}, Landroid/view/View;->setEnabled(Z)V\n    return-void\n.end method"
	reference, err := smalirole.AnalyzeCtx(smalirole.Request{Code: code, Line: 3}, r.Model, &smalirole.Ctx{})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := json.Marshal(map[string]any{"code": code, "line": 3})
	total := 0.0
	for _, p := range reference.Probs {
		total += p.P
	}
	for offset := range smalirole.Labels {
		criteria := "{"
		for i := range smalirole.Labels {
			if i > 0 {
				criteria += ","
			}
			key, _ := json.Marshal(smalirole.Labels[(i+offset)%len(smalirole.Labels)])
			criteria += string(key) + `:"Boolean flag bit mask duration limit or unknown"`
		}
		criteria += "}"
		resp, err := e.Decide(s1.Request{State: state, Questions: map[string]s1.Question{"role": {Type: s1.TypeChoice, Task: s1.TaskLiteralRole, Instructions: json.RawMessage(`"What is this literal's role?"`), Criteria: json.RawMessage(criteria)}}})
		if err != nil {
			t.Fatal(err)
		}
		a := resp.Answers["role"]
		if a.Source != "smalirole" {
			t.Fatalf("model bypassed at rotation %d: %s", offset, a.Source)
		}
		for _, p := range reference.Probs {
			want := p.P / total // System One returns a normalized distribution.
			if math.Abs(a.Probabilities.Get(p.Label)-want) > 0.00006 {
				t.Errorf("rotation %d moved probability of %s: want %.6f, got %.6f", offset, p.Label, want, a.Probabilities.Get(p.Label))
			}
		}
	}
}
