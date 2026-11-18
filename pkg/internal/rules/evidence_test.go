package rules

import "testing"

func TestSemanticFactsCannotBeForgedByLiteralOrComboInputs(t *testing.T) {
	e := NewEngine()
	ctx := &ConditionContext{Strings: []string{"crypto.file_encryption_flow"}, Patterns: []string{"android.legacy_js_bridge"}, Facts: map[string]bool{}}
	ctx.Build()
	if e.EvaluateCondition(Condition{Type: "fact", Value: "crypto.file_encryption_flow"}, ctx) {
		t.Fatal("a literal manufactured a semantic fact")
	}
	ctx.Facts["actual.fact"] = true
	if !e.EvaluateCondition(Condition{Type: "fact", Value: "actual.fact"}, ctx) {
		t.Fatal("semantic facts cannot be evaluated")
	}
	if e.EvaluateCondition(Condition{Type: "combo", Values: []string{"actual.fact"}}, ctx) {
		t.Fatal("combo text search treated a semantic fact as a literal")
	}
}

func TestPermissionOnlyThresholdDoesNotConfirmMalware(t *testing.T) {
	e := NewEngine()
	if err := e.LoadRulesFromBytes("test", []byte(`{"category":"banking_threats","version":"1","rules":[{"id":"profile","name":"Full control","severity":"critical","score":99,"enabled":true,"logic":"threshold","min_match":2,"conditions":[{"type":"permission","value":"READ_SMS"},{"type":"permission","value":"INTERNET"},{"type":"api_call","value":"exec"}]}]}`)); err != nil {
		t.Fatal(err)
	}
	items := e.EvaluateAll(&ConditionContext{Permissions: []string{"READ_SMS", "INTERNET"}})
	if len(items) != 1 || items[0].FindingKind != "inventory" || items[0].Severity != "info" || items[0].Score != 0 || len(items[0].Evidence) != 2 {
		t.Fatalf("permission threshold became a confirmed attack: %#v", items)
	}
}
