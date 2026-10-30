package report

import (
	"slices"
	"testing"
)

func TestSARIFRulesCarryTaxonomyTags(t *testing.T) {
	rules := buildSARIFRules([]sarifResult{{
		RuleID: "dataflow.command_injection", Level: "error",
		Properties: map[string]any{"cwe": []string{"CWE-78"}, "masvs": []string{"MASVS-CODE-4"}},
	}})
	if len(rules) != 1 {
		t.Fatalf("rules=%d", len(rules))
	}
	tags, ok := rules[0].Properties["tags"].([]string)
	if !ok || !slices.Contains(tags, "CWE-78") || !slices.Contains(tags, "MASVS-CODE-4") {
		t.Fatalf("taxonomy tags missing: %#v", rules[0].Properties)
	}
	if slices.Contains(tags, "network") {
		t.Fatalf("unrelated hardcoded network tag remains: %v", tags)
	}
}
