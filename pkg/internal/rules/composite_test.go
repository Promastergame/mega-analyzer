package rules

import (
	"strings"
	"testing"
)

const compositeRuleSet = `{
  "category": "test",
  "rules": [
    {"id":"a-overlay","name":"overlay","enabled":true,"severity":"high","score":40,
     "conditions":[{"type":"api_call","value":"TYPE_APPLICATION_OVERLAY"}]},
    {"id":"a-a11y","name":"a11y","enabled":true,"severity":"medium","score":30,
     "conditions":[{"type":"class","value":"accessibilityservice"}]},
    {"id":"c-trojan","name":"overlay+a11y","enabled":true,"severity":"critical","score":90,
     "confidence":0.8,
     "requires":["a-overlay","a-a11y"],
     "unless":["ctx-screenreader"],
     "downgrade":["ctx-mdm"]},
    {"id":"ctx-screenreader","name":"screen reader vendor","kind":"context","enabled":true,
     "reason":"TalkBack-style SDK legitimately combines overlay and accessibility",
     "conditions":[{"type":"class","value":"com/google/android/marvin/talkback"}]},
    {"id":"ctx-mdm","name":"MDM agent","kind":"context","enabled":true,
     "reason":"enterprise MDM agents overlay by design",
     "conditions":[{"type":"class","value":"devicepolicymanager"}]}
  ]
}`

func newCompositeEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine()
	if err := e.LoadRulesFromBytes("test", []byte(compositeRuleSet)); err != nil {
		t.Fatal(err)
	}
	return e
}

func ids(rs []RuleEvaluationResult) string {
	var out []string
	for _, r := range rs {
		out = append(out, r.RuleID)
	}
	return strings.Join(out, ",")
}

func TestCompositeFiresWhenAllMembersMatch(t *testing.T) {
	e := newCompositeEngine(t)
	ctx := &ConditionContext{APICalls: []string{"TYPE_APPLICATION_OVERLAY"}, Classes: []string{"x/accessibilityservice"}}
	res := e.EvaluateAll(ctx)
	if got := ids(res); got != "a-overlay,a-a11y,c-trojan" {
		t.Fatalf("unexpected results %q", got)
	}
	for _, r := range res {
		if r.RuleID == "c-trojan" && r.Confidence != 0.8 {
			t.Fatalf("confidence = %v, want 0.8", r.Confidence)
		}
		if r.RuleID == "a-a11y" && r.Confidence != 1.0 {
			t.Fatalf("default confidence = %v, want 1.0", r.Confidence)
		}
	}
}

func TestCompositeNeedsEveryMember(t *testing.T) {
	e := newCompositeEngine(t)
	ctx := &ConditionContext{APICalls: []string{"TYPE_APPLICATION_OVERLAY"}}
	if got := ids(e.EvaluateAll(ctx)); got != "a-overlay" {
		t.Fatalf("got %q, want only a-overlay", got)
	}
}

func TestUnlessSuppressesAndExplains(t *testing.T) {
	e := newCompositeEngine(t)
	ctx := &ConditionContext{
		APICalls: []string{"TYPE_APPLICATION_OVERLAY"},
		Classes:  []string{"x/accessibilityservice", "com/google/android/marvin/talkback/Service"},
	}
	ev := e.EvaluateDetailed(ctx)
	if strings.Contains(ids(ev.Results), "c-trojan") {
		t.Fatalf("composite must be suppressed, got %q", ids(ev.Results))
	}
	if len(ev.Suppressed) != 1 || ev.Suppressed[0].RuleID != "c-trojan" || ev.Suppressed[0].By != "ctx-screenreader" ||
		!strings.Contains(ev.Suppressed[0].Reason, "TalkBack") {
		t.Fatalf("suppression not recorded correctly: %+v", ev.Suppressed)
	}
}

func TestDowngradeKeepsFindingVisible(t *testing.T) {
	e := newCompositeEngine(t)
	ctx := &ConditionContext{
		APICalls: []string{"TYPE_APPLICATION_OVERLAY"},
		Classes:  []string{"x/accessibilityservice", "x/devicepolicymanager"},
	}
	var found *RuleEvaluationResult
	for _, r := range e.EvaluateAll(ctx) {
		r := r
		if r.RuleID == "c-trojan" {
			found = &r
		}
	}
	if found == nil {
		t.Fatal("downgraded finding must remain visible")
	}
	if found.Severity != "high" || found.Score != 45 || found.DowngradedBy != "ctx-mdm" {
		t.Fatalf("bad downgrade: %+v", *found)
	}
}

func TestContextRulesAreNeverEmitted(t *testing.T) {
	e := newCompositeEngine(t)
	ctx := &ConditionContext{Classes: []string{"com/google/android/marvin/talkback", "devicepolicymanager"}}
	if got := ids(e.EvaluateAll(ctx)); got != "" {
		t.Fatalf("context rules leaked into results: %q", got)
	}
}

func TestValidationContracts(t *testing.T) {
	cases := map[string]string{
		"context without reason": `{"id":"c","name":"c","kind":"context","conditions":[{"type":"class","value":"x"}]}`,
		"bad kind":               `{"id":"c","name":"c","kind":"weird","conditions":[{"type":"class","value":"x"}]}`,
		"bad confidence":         `{"id":"c","name":"c","confidence":1.5,"conditions":[{"type":"class","value":"x"}]}`,
		"self reference":         `{"id":"c","name":"c","requires":["c"]}`,
		"empty ref":              `{"id":"c","name":"c","requires":[" "]}`,
		"context with unless":    `{"id":"c","name":"c","kind":"context","reason":"r","unless":["x"],"conditions":[{"type":"class","value":"x"}]}`,
	}
	for name, rule := range cases {
		e := NewEngine()
		if err := e.LoadRulesFromBytes("t", []byte(`{"category":"t","rules":[`+rule+`]}`)); err != nil {
			t.Fatalf("%s: load error %v", name, err)
		}
		h := e.Health()
		if h.Skipped != 1 || h.Loaded != 0 || !h.Degraded() {
			t.Fatalf("%s: rule must be skipped and set degraded, health=%v", name, h)
		}
	}
}

func TestLintFindsBrokenGraph(t *testing.T) {
	e := NewEngine()
	set := `{"category":"t","rules":[
	 {"id":"a","name":"a","enabled":true,"requires":["b"]},
	 {"id":"b","name":"b","enabled":true,"requires":["a"]},
	 {"id":"d","name":"d","enabled":true,"conditions":[{"type":"class","value":"x"}],"requires":["ghost"],"unless":["plain"]},
	 {"id":"plain","name":"p","enabled":true,"conditions":[{"type":"class","value":"y"}]},
	 {"id":"orphan","name":"o","kind":"context","reason":"r","enabled":true,"conditions":[{"type":"class","value":"z"}]}
	]}`
	if err := e.LoadRulesFromBytes("t", []byte(set)); err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for _, is := range e.Lint() {
		msgs = append(msgs, is.String())
	}
	all := strings.Join(msgs, "\n")
	for _, want := range []string{"requires cycle", `unknown rule "ghost"`, `not a context rule`, "matches no rule"} {
		if !strings.Contains(all, want) {
			t.Errorf("lint output lacks %q:\n%s", want, all)
		}
	}
	if !e.Health().Degraded() {
		t.Fatal("lint errors must degrade health")
	}
	// Цикл не должен зависнуть при оценке.
	_ = e.EvaluateAll(&ConditionContext{Classes: []string{"x"}})
}

func TestCleanSetIsNotDegraded(t *testing.T) {
	e := newCompositeEngine(t)
	if h := e.Health(); h.Degraded() || h.Loaded != 5 {
		t.Fatalf("health = %v", h)
	}
	if issues := e.Lint(); len(issues) != 0 {
		t.Fatalf("unexpected lint issues: %v", issues)
	}
}

func TestCompositeInheritsFileScope(t *testing.T) {
	e := NewEngine()
	set := `{"category":"t","rules":[
	 {"id":"m1","name":"m1","enabled":true,"conditions":[{"type":"api_call","value":"a"},{"type":"class","value":"b"}]},
	 {"id":"comp","name":"comp","enabled":true,"requires":["m1"]},
	 {"id":"comp-global","name":"cg","enabled":true,"scope":"global","requires":["m1"]}
	]}`
	if err := e.LoadRulesFromBytes("t", []byte(set)); err != nil {
		t.Fatal(err)
	}
	comp, _ := e.GetRuleByID("comp")
	if !comp.IsFileScoped() {
		t.Fatal("composite of a file-scoped member must be file-scoped")
	}
	cg, _ := e.GetRuleByID("comp-global")
	if cg.IsFileScoped() {
		t.Fatal("explicit scope must win")
	}
}

func TestDuplicateIDIsSkipped(t *testing.T) {
	e := NewEngine()
	set := `{"category":"t","rules":[
	 {"id":"a","name":"a","enabled":true,"conditions":[{"type":"class","value":"x"}]},
	 {"id":"a","name":"a2","enabled":true,"conditions":[{"type":"class","value":"y"}]}
	]}`
	_ = e.LoadRulesFromBytes("t", []byte(set))
	if h := e.Health(); h.Loaded != 1 || h.Skipped != 1 {
		t.Fatalf("health = %v", h)
	}
}

func TestReloadCategoryResetsSkipped(t *testing.T) {
	e := NewEngine()
	_ = e.LoadRulesFromBytes("t", []byte(`{"category":"t","rules":[{"id":"","name":"x"}]}`))
	if !e.Health().Degraded() {
		t.Fatal("expected degraded")
	}
	_ = e.LoadRulesFromBytes("t", []byte(`{"category":"t","rules":[{"id":"ok","name":"ok","enabled":true,"conditions":[{"type":"class","value":"x"}]}]}`))
	if e.Health().Degraded() {
		t.Fatal("reload with a clean set must clear degradation")
	}
}

func TestSelectorContextRules(t *testing.T) {
	e := NewEngine()
	set := `{"category":"bank","rules":[
	 {"id":"bank_overlay","name":"o","enabled":true,"severity":"critical","score":98,"tags":["overlay"],
	  "conditions":[{"type":"api_call","value":"overlay"}]},
	 {"id":"bank_keylog","name":"k","enabled":true,"severity":"high","score":60,
	  "conditions":[{"type":"api_call","value":"keylog"}]},
	 {"id":"rat_shell","name":"r","enabled":true,"severity":"critical","score":90,"tags":["rat"],
	  "conditions":[{"type":"api_call","value":"exec"}]},
	 {"id":"other","name":"x","enabled":true,"severity":"low","score":10,
	  "conditions":[{"type":"api_call","value":"other"}]},
	 {"id":"ctx_vendor","name":"vendor","kind":"context","enabled":true,"reason":"vendor SDK",
	  "suppresses":["bank_keylog"],"downgrades":["tag:overlay","category:none","rat_*"],
	  "conditions":[{"type":"class","value":"vendor/sdk"}]}
	]}`
	if err := e.LoadRulesFromBytes("t", []byte(set)); err != nil {
		t.Fatal(err)
	}
	if issues := e.Lint(); len(issues) != 0 {
		t.Fatalf("lint: %v", issues)
	}
	ctx := &ConditionContext{
		APICalls: []string{"overlay", "keylog", "exec", "other"},
		Classes:  []string{"vendor/sdk/Main"},
	}
	ev := e.EvaluateDetailed(ctx)
	got := map[string]RuleEvaluationResult{}
	for _, r := range ev.Results {
		got[r.RuleID] = r
	}
	if _, ok := got["bank_keylog"]; ok {
		t.Fatal("bank_keylog must be suppressed by selector")
	}
	if got["bank_overlay"].Severity != "high" || got["bank_overlay"].DowngradedBy != "ctx_vendor" {
		t.Fatalf("tag selector failed: %+v", got["bank_overlay"])
	}
	if got["rat_shell"].Severity != "high" {
		t.Fatalf("prefix selector failed: %+v", got["rat_shell"])
	}
	if got["other"].Severity != "low" || got["other"].DowngradedBy != "" {
		t.Fatalf("unrelated rule must be untouched: %+v", got["other"])
	}
	if len(ev.Suppressed) != 1 || ev.Suppressed[0].By != "ctx_vendor" {
		t.Fatalf("suppression log: %+v", ev.Suppressed)
	}
	// Без сработавшего контекста ничего не меняется.
	ev = e.EvaluateDetailed(&ConditionContext{APICalls: []string{"overlay", "keylog"}})
	if len(ev.Results) != 2 || len(ev.Suppressed) != 0 {
		t.Fatalf("context absent, results must be untouched: %+v", ev)
	}
}

func TestSelectorValidation(t *testing.T) {
	for name, rule := range map[string]string{
		"selector on detect rule": `{"id":"a","name":"a","suppresses":["x"],"conditions":[{"type":"class","value":"x"}]}`,
		"catch-all selector":      `{"id":"a","name":"a","kind":"context","reason":"r","suppresses":["*"],"conditions":[{"type":"class","value":"x"}]}`,
	} {
		e := NewEngine()
		_ = e.LoadRulesFromBytes("t", []byte(`{"category":"t","rules":[`+rule+`]}`))
		if e.Health().Skipped != 1 {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
