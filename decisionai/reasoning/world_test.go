package reasoning

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRelationProofsAndNegation(t *testing.T) {
	for _, tc := range []struct {
		name, text, query, status string
		steps                     int
	}{
		{"en_chain", "Mira is taller than Oren. Oren is taller than Tavi.", "Is Mira taller than Tavi?", "supported", 3},
		{"ru_chain", "Лена выше Тимура. Тимур выше Олега.", "Лена выше Олега?", "supported", 3},
		{"inverse_query", "Mira taller than Oren.", "Is Oren taller than Mira?", "refuted", 1},
		{"negative_inverse", "Mira taller than Oren.", "Is Oren not taller than Mira?", "supported", 1},
		{"negative_not_opposite", "Mira not taller than Oren.", "Is Oren taller than Mira?", "unknown", 0},
		{"explicit_negative", "Mira not taller than Oren.", "Is Mira taller than Oren?", "refuted", 1},
		{"younger_chain", "Mira younger than Oren. Oren younger than Tavi.", "Is Mira younger than Tavi?", "supported", 3},
		{"time_same", "Mira taller than Oren yesterday. Oren taller than Tavi yesterday.", "Is Mira taller than Tavi yesterday?", "supported", 3},
		{"time_separate", "Mira taller than Oren yesterday. Oren taller than Tavi today.", "Is Mira taller than Tavi today?", "unknown", 0},
		{"time_unspecified", "Mira taller than Oren yesterday.", "Is Mira taller than Oren?", "unknown", 0},
		{"missing_relation", "Mira taller than Oren. Tavi taller than Niko.", "Is Mira taller than Niko?", "unknown", 0},
		{"different_dimension", "Mira older than Oren.", "Is Mira taller than Oren?", "unknown", 0},
		{"contradiction", "Mira taller than Oren. Mira not taller than Oren.", "Is Mira taller than Oren?", "conflict", 2},
		{"strict_cycle", "Mira taller than Oren. Oren taller than Mira.", "Is Mira taller than Oren?", "conflict", 2},
		{"cycle_no_explosion", "Mira taller than Oren. Oren taller than Mira. Oren taller than Tavi.", "Is Mira taller than Tavi?", "unknown", 0},
		{"question_not_fact", "Mira taller than Oren?", "Is Mira taller than Oren?", "unknown", 0},
		{"conditional_not_fact", "If Mira taller than Oren.", "Is Mira taller than Oren?", "unknown", 0},
		{"pronoun_not_bound", "She taller than Oren.", "Is Mira taller than Oren?", "unknown", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, ok := ParseClaim(tc.query)
			if !ok {
				t.Fatal("query did not parse")
			}
			w := New()
			q = w.ReadText(tc.text, []Atom{q})[0]
			w.Solve()
			got := w.Query(q)
			if got.Status != tc.status || len(got.Proof) != tc.steps {
				t.Fatalf("got %+v, want %s / %d steps; limited=%s", got, tc.status, tc.steps, w.LimitReason)
			}
			seen := map[int]bool{}
			for _, step := range got.Proof {
				for _, premise := range step.Premises {
					if !seen[premise] {
						t.Fatalf("missing earlier premise %d in %+v", premise, got.Proof)
					}
				}
				if step.Source == "" {
					t.Fatal("missing source")
				}
				seen[step.ID] = true
			}
		})
	}
}

func TestRuleSourceNamesDoNotChangeSemantics(t *testing.T) {
	for _, source := range []string{"transitivity:taller", "transitivity:custom", "ordinary-policy"} {
		t.Run(source, func(t *testing.T) {
			w := New()
			w.Add(Atom{Subject: "mira", Predicate: "taller", Object: "oren"}, "first")
			w.Add(Atom{Subject: "oren", Predicate: "taller", Object: "tavi"}, "second")
			w.Add(Atom{Subject: "mira", Predicate: "input"}, "input")
			w.AddRule(Rule{All: []Atom{{Subject: "$x", Predicate: "input"}}, Then: Atom{Subject: "$x", Predicate: "self_reference", Object: "$x"}, Source: source})
			w.Solve()
			for i, query := range []Atom{
				{Subject: "mira", Predicate: "taller", Object: "tavi"},
				{Subject: "mira", Predicate: "self_reference", Object: "mira"},
			} {
				got := w.Query(query)
				if got.Status != "supported" {
					t.Fatalf("source metadata changed inference: %+v", got)
				}
				if got.Proof[len(got.Proof)-1].Builtin != (i == 0) {
					t.Fatal("source metadata changed derivation provenance", got)
				}
			}
			count := len(w.Rules)
			w.Solve()
			if len(w.Rules) != count {
				t.Fatal("repeated solve duplicated an intrinsic rule")
			}
		})
	}
}

func TestRulesBindAllPremisesAndRequireExplicitNegation(t *testing.T) {
	w := New()
	w.Add(Atom{Subject: "Mira", Predicate: "paid"}, "receipt")
	w.Add(Atom{Subject: "Oren", Predicate: "verified"}, "audit")
	w.AddRule(Rule{All: []Atom{{Subject: "$x", Predicate: "paid"}, {Subject: "$x", Predicate: "verified"}}, Then: Atom{Subject: "$x", Predicate: "ready"}, Source: "access-policy"})
	w.AddRule(Rule{All: []Atom{{Subject: "$x", Predicate: "banned", Negated: true}}, Then: Atom{Subject: "$x", Predicate: "eligible"}, Source: "eligibility-policy"})
	w.Solve()
	if got := w.Query(Atom{Subject: "Mira", Predicate: "ready"}); got.Status != "unknown" {
		t.Fatal("mixed entities satisfied conditions", got)
	}
	if got := w.Query(Atom{Subject: "Mira", Predicate: "eligible"}); got.Status != "unknown" {
		t.Fatal("missing fact was treated as negation", got)
	}
	w.Add(Atom{Subject: "Mira", Predicate: "verified"}, "identity-check")
	w.Solve()
	got := w.Query(Atom{Subject: "Mira", Predicate: "ready"})
	if got.Status != "supported" || len(got.Proof) != 3 {
		t.Fatal(got)
	}
}

func TestConflictingDerivedPremiseCannotSupportConclusion(t *testing.T) {
	w := New()
	w.Add(Atom{Subject: "mira", Predicate: "input"}, "input")
	w.AddRule(Rule{All: []Atom{{Subject: "mira", Predicate: "input"}}, Then: Atom{Subject: "mira", Predicate: "ready"}, Source: "yes-rule"})
	w.AddRule(Rule{All: []Atom{{Subject: "mira", Predicate: "ready"}}, Then: Atom{Subject: "mira", Predicate: "allowed"}, Source: "allow-rule"})
	w.AddRule(Rule{All: []Atom{{Subject: "mira", Predicate: "input"}}, Then: Atom{Subject: "mira", Predicate: "ready", Negated: true}, Source: "no-rule"})
	w.Solve()
	if got := w.Query(Atom{Subject: "mira", Predicate: "ready"}); got.Status != "conflict" {
		t.Fatal(got)
	}
	if got := w.Query(Atom{Subject: "mira", Predicate: "allowed"}); got.Status != "unknown" {
		t.Fatal("invalidated proof stayed supported", got)
	}
	w.Add(Atom{Subject: "mira", Predicate: "independent"}, "independent-input")
	w.AddRule(Rule{All: []Atom{{Subject: "mira", Predicate: "independent"}}, Then: Atom{Subject: "mira", Predicate: "allowed"}, Source: "independent-rule"})
	w.Solve()
	got := w.Query(Atom{Subject: "mira", Predicate: "allowed"})
	if got.Status != "supported" || len(got.Proof) != 2 || got.Proof[1].Source != "independent-rule" {
		t.Fatal("independent proof was lost", got)
	}
}

func TestOnlyDeclaredTransitivePredicates(t *testing.T) {
	w := New()
	w.Add(Atom{Subject: "mira", Predicate: "gave_to", Object: "oren"}, "first")
	w.Add(Atom{Subject: "oren", Predicate: "gave_to", Object: "tavi"}, "second")
	w.Solve()
	if got := w.Query(Atom{Subject: "mira", Predicate: "gave_to", Object: "tavi"}); got.Status != "unknown" {
		t.Fatal(got)
	}
}

func TestWorkBudgetAndRepeatedSolve(t *testing.T) {
	w := New()
	for i := 0; i < 40; i++ {
		w.Add(Atom{Subject: fmt.Sprintf("e%d", i), Predicate: "taller", Object: fmt.Sprintf("e%d", i+1)}, "input")
	}
	w.Solve()
	if !w.Limited || w.Work > MaxWork || w.LimitReason == "" {
		t.Fatalf("budget not enforced: %+v", w)
	}
	if got := w.Query(Atom{Subject: "e0", Predicate: "taller", Object: "e1"}); got.Status != "unknown" {
		t.Fatal("incomplete closure certified a result", got)
	}
	clean := New()
	clean.Add(Atom{Subject: "a", Predicate: "taller", Object: "b"}, "input")
	clean.Solve()
	rules := len(clean.Rules)
	clean.Solve()
	if clean.Limited || len(clean.Rules) != rules {
		t.Fatal("repeated solve duplicated built-in rules")
	}
}

func TestStructuredValidationAndCurrentScope(t *testing.T) {
	for _, raw := range []string{
		`{"facts":[{"subject":" $x","predicate":"ready"}]}`,
		`{"facts":[{"subject":"a","predicate":"ready","time":"$t"}]}`,
		`{"rules":[{"all":[{"subject":"$x","predicate":"p"}],"then":{"subject":"$y","predicate":"q"}}]}`,
		`{"rules":[{"all":[{"subject":"$x","predicate":""}],"then":{"subject":"$x","predicate":"q"}}]}`,
	} {
		var state any
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			t.Fatal(err)
		}
		if recognized, err := New().FromJSON(state); !recognized || err == nil {
			t.Fatalf("invalid structure accepted: %s", raw)
		}
	}
	var state any
	json.Unmarshal([]byte(`{"archive":{"facts":[{"subject":"mira","predicate":"ready"}]},"current":{"facts":[{"subject":"oren","predicate":"ready"}]}}`), &state)
	w := New()
	if ok, err := w.FromJSON(state); !ok || err != nil {
		t.Fatal(ok, err)
	}
	w.Solve()
	if got := w.Query(Atom{Subject: "mira", Predicate: "ready"}); got.Status != "unknown" {
		t.Fatal("archive leaked", got)
	}
	if got := w.Query(Atom{Subject: "oren", Predicate: "ready"}); got.Status != "supported" || strings.Contains(got.Proof[0].Source, "archive") {
		t.Fatal(got)
	}
}
