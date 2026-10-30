package binzap

import (
	"os"
	"testing"
)

func TestDynamicBinzapRulesCRUD(t *testing.T) {
	oldPath := dynamicBinzapFilePath
	dynamicBinzapFilePath = "configs/dynamic_rules/binzap_rules_test.json"
	defer func() {
		_ = os.Remove(dynamicBinzapFilePath)
		dynamicBinzapFilePath = oldPath
	}()

	dynamicBinzapRules = []DynamicBinzapRule{}

	rule := DynamicBinzapRule{
		IDStr:       "BZ-DYN-TEST",
		NameStr:     "Test Custom Bytecode Matcher",
		SeverityVal: SeverityMedium,
		Steps: []PatternStep{
			{Type: "opcode", Value: "const-string"},
			{Type: "any_register"},
		},
	}

	// 1. Add rule
	err := AddDynamicBinzapRule(rule)
	if err != nil {
		t.Fatalf("Failed to add binzap rule: %v", err)
	}

	// 2. Fetch rules
	rules := GetRawDynamicBinzapRules()
	if len(rules) != 1 || rules[0].IDStr != "BZ-DYN-TEST" {
		t.Fatalf("Expected 1 rule with ID 'BZ-DYN-TEST', got: %v", rules)
	}

	// 3. Update rule
	rule.NameStr = "Updated Custom Bytecode Matcher"
	err = UpdateDynamicBinzapRule("BZ-DYN-TEST", rule)
	if err != nil {
		t.Fatalf("Failed to update binzap rule: %v", err)
	}

	rules = GetRawDynamicBinzapRules()
	if rules[0].NameStr != "Updated Custom Bytecode Matcher" {
		t.Fatalf("Expected name 'Updated Custom Bytecode Matcher', got: %s", rules[0].NameStr)
	}

	// 4. Delete rule
	err = DeleteDynamicBinzapRule("BZ-DYN-TEST")
	if err != nil {
		t.Fatalf("Failed to delete binzap rule: %v", err)
	}

	rules = GetRawDynamicBinzapRules()
	if len(rules) != 0 {
		t.Fatalf("Expected 0 rules remaining, got: %d", len(rules))
	}
}
