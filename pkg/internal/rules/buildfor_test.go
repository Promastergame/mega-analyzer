package rules

import (
	"strings"
	"testing"
)

// The shipped rule sets never set "exact", so every condition takes the
// substring path and the six exact-match indexes are dead weight. These tests
// pin the sizing logic that skips them.

func testContext() *ConditionContext {
	return &ConditionContext{
		Permissions: []string{"android.permission.INTERNET"},
		APICalls:    []string{"Ljava/net/URL;->openConnection"},
		Patterns:    []string{"shared", "pattern-only"},
		Strings:     []string{"shared", "string-only"},
		Classes:     []string{"Lcom/example/A;"},
		Methods:     []string{"onCreate"},
	}
}

func TestBuildForSkipsUnusedIndexes(t *testing.T) {
	ctx := testContext()
	ctx.BuildFor(false, false)

	if !ctx.built {
		t.Fatal("BuildFor must mark the context as built")
	}
	if ctx.permSet != nil || ctx.apiSet != nil || ctx.patternSet != nil ||
		ctx.stringSet != nil || ctx.classSet != nil || ctx.methodSet != nil {
		t.Error("exact-match sets were built even though no rule can read them")
	}
	if ctx.allValues != nil {
		t.Error("allValues was built even though no non-exact combo rule exists")
	}
}

func TestBuildForBuildsWhatIsAsked(t *testing.T) {
	ctx := testContext()
	ctx.BuildFor(true, false)
	if len(ctx.permSet) != 1 || len(ctx.methodSet) != 1 {
		t.Error("sets requested but not built")
	}
	if ctx.allValues != nil {
		t.Error("allValues built without being requested")
	}

	ctx = testContext()
	ctx.BuildFor(false, true)
	if ctx.permSet != nil {
		t.Error("sets built without being requested")
	}
	if len(ctx.allValues) == 0 {
		t.Error("allValues requested but not built")
	}
}

// Build must stay a full build: it is the public entry point and existing
// callers rely on every index being present afterwards.
func TestBuildStillMaterialisesEverything(t *testing.T) {
	ctx := testContext()
	ctx.Build()

	if len(ctx.permSet) == 0 || len(ctx.apiSet) == 0 || len(ctx.patternSet) == 0 ||
		len(ctx.stringSet) == 0 || len(ctx.classSet) == 0 || len(ctx.methodSet) == 0 {
		t.Error("Build must materialise all six exact-match sets")
	}
	if len(ctx.allValues) == 0 {
		t.Error("Build must materialise allValues")
	}
}

// The pipeline pushes identical content into Patterns and Strings, so the
// union used to carry duplicates. Dropping them must not change any answer a
// substring search can give.
func TestAllValuesIsDedupedWithoutLosingContent(t *testing.T) {
	ctx := testContext()
	ctx.BuildFor(false, true)

	seen := map[string]int{}
	for _, v := range ctx.allValues {
		seen[v]++
	}
	for v, n := range seen {
		if n > 1 {
			t.Errorf("allValues still contains %q %d times", v, n)
		}
	}

	for _, want := range []string{
		"android.permission.INTERNET",
		"Ljava/net/URL;->openConnection",
		"shared", "pattern-only", "string-only",
		"Lcom/example/A;", "onCreate",
	} {
		if !containsSubstring(ctx.allValues, want) {
			t.Errorf("dedup dropped %q from the combo corpus", want)
		}
	}
}

const capabilityRules = `{
  "category": "caps",
  "version": "1",
  "rules": [
    {"id":"r_sub","name":"Substring only","severity":"low","score":10,"enabled":true,
     "conditions":[{"type":"string","value":"alpha"}]}
  ]
}`

const capabilityRulesExact = `{
  "category": "caps_exact",
  "version": "1",
  "rules": [
    {"id":"r_exact","name":"Exact","severity":"low","score":10,"enabled":true,
     "conditions":[{"type":"string","value":"alpha","exact":true}]}
  ]
}`

const capabilityRulesCombo = `{
  "category": "caps_combo",
  "version": "1",
  "rules": [
    {"id":"r_combo","name":"Combo","severity":"low","score":10,"enabled":true,
     "conditions":[{"type":"combo","values":["alpha","beta"]}]}
  ]
}`

func TestCapabilityFlagsReflectLoadedRules(t *testing.T) {
	t.Run("substring only needs neither index", func(t *testing.T) {
		e := NewEngine()
		if err := e.LoadRulesFromBytes("caps", []byte(capabilityRules)); err != nil {
			t.Fatalf("load: %v", err)
		}
		if e.needsExactSets {
			t.Error("no exact condition is loaded, sets should not be needed")
		}
		if e.needsAllValues {
			t.Error("no combo condition is loaded, allValues should not be needed")
		}
	})

	t.Run("exact condition turns sets on", func(t *testing.T) {
		e := NewEngine()
		if err := e.LoadRulesFromBytes("caps", []byte(capabilityRulesExact)); err != nil {
			t.Fatalf("load: %v", err)
		}
		if !e.needsExactSets {
			t.Error("an exact condition is loaded but sets are still skipped")
		}
	})

	t.Run("non-exact combo turns allValues on", func(t *testing.T) {
		e := NewEngine()
		if err := e.LoadRulesFromBytes("caps", []byte(capabilityRulesCombo)); err != nil {
			t.Fatalf("load: %v", err)
		}
		if !e.needsAllValues {
			t.Error("a non-exact combo is loaded but allValues is still skipped")
		}
	})
}

// A rule evaluated through the engine must reach the same verdict whether or
// not the caller pre-built the context. This is the safety net for dropping
// the eager ctx.Build() in the pipeline.
func TestEvaluationAgreesWithAndWithoutPrebuiltContext(t *testing.T) {
	e := NewEngine()
	if err := e.LoadRulesFromBytes("caps", []byte(capabilityRules)); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := e.LoadRulesFromBytes("caps_combo", []byte(capabilityRulesCombo)); err != nil {
		t.Fatalf("load: %v", err)
	}

	collect := func(prebuilt bool) []string {
		ctx := &ConditionContext{Strings: []string{"alpha"}, Patterns: []string{"beta"}}
		if prebuilt {
			ctx.Build()
		}
		var ids []string
		for _, r := range e.EvaluateAll(ctx) {
			ids = append(ids, r.RuleID)
		}
		return ids
	}

	with := collect(true)
	without := collect(false)
	if len(with) != len(without) {
		t.Fatalf("verdict changed: prebuilt=%v lazy=%v", with, without)
	}
	sortJoin := func(in []string) string {
		out := append([]string(nil), in...)
		for i := range out {
			for j := i + 1; j < len(out); j++ {
				if out[j] < out[i] {
					out[i], out[j] = out[j], out[i]
				}
			}
		}
		return strings.Join(out, ",")
	}
	if sortJoin(with) != sortJoin(without) {
		t.Fatalf("verdict changed: prebuilt=%v lazy=%v", with, without)
	}
}

// IsFileScoped is now cached at load time. The cache must agree with the
// computation it replaces, for every shipped scope spelling.
func TestResolveScopeMatchesComputation(t *testing.T) {
	cases := []Rule{
		{ID: "a", Scope: "file", Conditions: []Condition{{Type: "string", Value: "x"}}},
		{ID: "b", Scope: "class", Conditions: []Condition{{Type: "string", Value: "x"}}},
		{ID: "c", Scope: "global", Conditions: []Condition{{Type: "string", Value: "x"}, {Type: "api_call", Value: "y"}}},
		{ID: "d", Scope: "apk", Conditions: []Condition{{Type: "string", Value: "x"}}},
		{ID: "e", Scope: "", Conditions: []Condition{{Type: "permission", Value: "p"}}},
		{ID: "f", Scope: "", Conditions: []Condition{{Type: "string", Value: "x"}, {Type: "api_call", Value: "y"}}},
		{ID: "g", Scope: "", Conditions: []Condition{{Type: "combo", Values: []string{"x", "y"}}}},
		{ID: "h", Scope: "FILE", Conditions: []Condition{{Type: "string", Value: "x"}}},
	}

	for i := range cases {
		r := cases[i]
		want := r.computeFileScoped()

		cached := cases[i]
		cached.resolveScope()
		if got := cached.IsFileScoped(); got != want {
			t.Errorf("rule %q: cached scope %v, computed %v", r.ID, got, want)
		}

		// An unresolved rule must still answer correctly.
		fresh := cases[i]
		if got := fresh.IsFileScoped(); got != want {
			t.Errorf("rule %q: uncached scope %v, computed %v", r.ID, got, want)
		}
	}
}

func TestLoadedRulesHaveResolvedScope(t *testing.T) {
	e := NewEngine()
	if err := e.LoadRulesFromBytes("caps", []byte(capabilityRules)); err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, set := range e.rules {
		for i := range set {
			if !set[i].scopeResolved {
				t.Errorf("rule %q was published without a resolved scope", set[i].ID)
			}
		}
	}
}
