package vulnscan

import (
	"os"
	"testing"
)

func TestDynamicWebRulesCRUD(t *testing.T) {
	// Temporarily redirect file path for testing
	oldPath := dynamicWebFilePath
	dynamicWebFilePath = "configs/dynamic_rules/web_rules_test.json"
	defer func() {
		_ = os.Remove(dynamicWebFilePath)
		dynamicWebFilePath = oldPath
	}()

	// Clear existing rules
	dynamicWebRules = []DynamicWebRule{}

	rule := DynamicWebRule{
		ID:           "WS-DYN-TEST",
		Name:         "Test Custom Dynamic Rule",
		Description:  "Verify active regex patterns match.",
		Severity:     SeverityHigh,
		Type:         "regex_passive",
		RegexPattern: "test-token-[0-9]+",
	}

	// 1. Add rule
	err := AddDynamicWebRule(rule)
	if err != nil {
		t.Fatalf("Failed to add web rule: %v", err)
	}

	// 2. Fetch rules
	rules := GetDynamicWebRules()
	if len(rules) != 1 || rules[0].ID != "WS-DYN-TEST" {
		t.Fatalf("Expected 1 rule with ID 'WS-DYN-TEST', got: %v", rules)
	}

	// 3. Update rule
	rule.Name = "Updated Custom Dynamic Rule"
	err = UpdateDynamicWebRule("WS-DYN-TEST", rule)
	if err != nil {
		t.Fatalf("Failed to update web rule: %v", err)
	}

	rules = GetDynamicWebRules()
	if rules[0].Name != "Updated Custom Dynamic Rule" {
		t.Fatalf("Expected name 'Updated Custom Dynamic Rule', got: %s", rules[0].Name)
	}

	// 4. Delete rule
	err = DeleteDynamicWebRule("WS-DYN-TEST")
	if err != nil {
		t.Fatalf("Failed to delete web rule: %v", err)
	}

	rules = GetDynamicWebRules()
	if len(rules) != 0 {
		t.Fatalf("Expected 0 rules remaining, got: %d", len(rules))
	}
}
