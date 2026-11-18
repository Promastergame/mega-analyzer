package rules

import (
	"testing"

	"mega-analyzer/pkg/internal/configs"
)

func TestShippedLocaleAndHashStorageAreNotThreatClaims(t *testing.T) {
	e := NewEngine()
	for _, name := range []string{"banking_threats.json", "malware_combos.json"} {
		data, ok := configs.File(name)
		if !ok {
			t.Fatalf("shipped rule set %s not found", name)
		}
		if err := e.LoadRulesFromBytes(name, data); err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
	}
	evaluate := func(ctx *ConditionContext) map[string]RuleEvaluationResult {
		ctx.Build()
		out := make(map[string]RuleEvaluationResult)
		for _, result := range e.EvaluateAll(ctx) {
			out[result.RuleID] = result
		}
		return out
	}
	ctx := &ConditionContext{APICalls: []string{"getSimCountryIso", "getNetworkCountryIso", "getCountry", "TimeZone.getDefault", "SharedPreferences", "putString"}, Patterns: []string{"getAppPasswordHash"}}
	fired := evaluate(ctx)
	for _, id := range []string{"bank_evasion_geo_targeting", "evasion_country_check"} {
		if result, ok := fired[id]; ok && (result.Severity != "info" || result.Score != 0) {
			t.Errorf("locale API observation is still a threat: %+v", result)
		}
	}
	if _, ok := fired["insecure_storage_credentials"]; ok {
		t.Error("password hash plus unrelated preference writes fired credential storage")
	}
	ctx = &ConditionContext{Facts: map[string]bool{"storage.plaintext_credential_write": true}}
	if _, ok := evaluate(ctx)["insecure_storage_credentials"]; !ok {
		t.Error("proven plaintext credential write was lost")
	}
}
