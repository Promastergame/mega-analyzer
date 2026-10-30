package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func createTempRuleFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test_rules.json")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp rule file: %v", err)
	}
	return filePath
}

func createTestRuleSet() RuleSet {
	return RuleSet{
		Category:    "test",
		Version:     "1.0",
		Description: "Test rules",
		Rules: []Rule{
			{
				ID:          "TEST001",
				Name:        "Test Rule 1",
				Description: "First test rule",
				Category:    "test",
				Severity:    "high",
				Score:       75,
				Enabled:     true,
				Conditions: []Condition{
					{Type: "permission", Value: "android.permission.READ_SMS"},
				},
			},
			{
				ID:          "TEST002",
				Name:        "Test Rule 2",
				Description: "Second test rule",
				Category:    "test",
				Severity:    "medium",
				Score:       50,
				Enabled:     true,
				Conditions: []Condition{
					{Type: "api_call", Value: "Landroid/telephony/SmsManager;"},
				},
			},
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rule",
			rule: Rule{
				ID:       "R001",
				Name:     "Valid Rule",
				Severity: "high",
				Score:    50,
				Enabled:  true,
				Conditions: []Condition{
					{Type: "permission", Value: "android.permission.INTERNET"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			rule: Rule{
				ID:   "",
				Name: "No ID Rule",
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "empty ID",
		},
		{
			name: "empty Name",
			rule: Rule{
				ID:   "R001",
				Name: "",
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "empty Name",
		},
		{
			name: "no conditions",
			rule: Rule{
				ID:         "R001",
				Name:       "No Conditions",
				Conditions: []Condition{},
			},
			wantErr: true,
			errMsg:  "no conditions",
		},
		{
			name: "invalid score negative",
			rule: Rule{
				ID:    "R001",
				Name:  "Invalid Score",
				Score: -10,
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "invalid score",
		},
		{
			name: "invalid score over 100",
			rule: Rule{
				ID:    "R001",
				Name:  "Invalid Score",
				Score: 150,
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "invalid score",
		},
		{
			name: "invalid severity",
			rule: Rule{
				ID:       "R001",
				Name:     "Invalid Severity",
				Severity: "super_critical",
				Score:    50,
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "invalid severity",
		},
		{
			name: "invalid condition type",
			rule: Rule{
				ID:    "R001",
				Name:  "Invalid Condition Type",
				Score: 50,
				Conditions: []Condition{
					{Type: "unknown_type", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "invalid type",
		},
		{
			name: "combo without values",
			rule: Rule{
				ID:    "R001",
				Name:  "Empty Combo",
				Score: 50,
				Conditions: []Condition{
					{Type: "combo", Values: []string{}},
				},
			},
			wantErr: true,
			errMsg:  "Values is empty",
		},
		{
			name: "condition with empty value",
			rule: Rule{
				ID:    "R001",
				Name:  "Empty Value",
				Score: 50,
				Conditions: []Condition{
					{Type: "permission", Value: ""},
				},
			},
			wantErr: true,
			errMsg:  "empty Value",
		},
		{
			name: "threshold without MinMatch",
			rule: Rule{
				ID:       "R001",
				Name:     "Bad Threshold",
				Score:    50,
				Logic:    "threshold",
				MinMatch: 0,
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "MinMatch",
		},
		{
			name: "valid combo rule",
			rule: Rule{
				ID:    "R001",
				Name:  "Valid Combo",
				Score: 50,
				Conditions: []Condition{
					{Type: "combo", Values: []string{"val1", "val2"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid threshold rule",
			rule: Rule{
				ID:       "R001",
				Name:     "Valid Threshold",
				Score:    50,
				Logic:    "threshold",
				MinMatch: 2,
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
					{Type: "permission", Value: "perm2"},
					{Type: "permission", Value: "perm3"},
				},
			},
			wantErr: false,
		},
		{
			name: "all valid severities",
			rule: Rule{
				ID:       "R001",
				Name:     "Critical",
				Severity: "critical",
				Score:    100,
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "info severity",
			rule: Rule{
				ID:       "R002",
				Name:     "Info",
				Severity: "info",
				Score:    10,
				Conditions: []Condition{
					{Type: "permission", Value: "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "all condition types valid",
			rule: Rule{
				ID:    "R001",
				Name:  "All Types",
				Score: 50,
				Conditions: []Condition{
					{Type: "permission", Value: "perm"},
					{Type: "api_call", Value: "api"},
					{Type: "pattern", Value: "pattern"},
					{Type: "class", Value: "class"},
					{Type: "method", Value: "method"},
					{Type: "string", Value: "string"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, should contain %q", err, tt.errMsg)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewEngine(t *testing.T) {
	engine := NewEngine()

	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}

	if engine.rules == nil {
		t.Error("engine.rules is nil")
	}

	if engine.ruleByID == nil {
		t.Error("engine.ruleByID is nil")
	}

	stats := engine.Stats()
	if stats.TotalRules != 0 {
		t.Errorf("new engine should have 0 rules, got %d", stats.TotalRules)
	}
}

func TestEngine_LoadRulesFromFile(t *testing.T) {
	t.Run("valid rules file", func(t *testing.T) {
		engine := NewEngine()
		ruleSet := createTestRuleSet()

		data, _ := json.Marshal(ruleSet)
		filePath := createTempRuleFile(t, string(data))

		err := engine.LoadRulesFromFile(filePath)
		if err != nil {
			t.Fatalf("LoadRulesFromFile() error = %v", err)
		}

		stats := engine.Stats()
		if stats.TotalRules != 2 {
			t.Errorf("expected 2 rules, got %d", stats.TotalRules)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		engine := NewEngine()
		err := engine.LoadRulesFromFile("/nonexistent/path/rules.json")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		engine := NewEngine()
		filePath := createTempRuleFile(t, "{ invalid json }")

		err := engine.LoadRulesFromFile(filePath)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("empty category defaults to 'default'", func(t *testing.T) {
		engine := NewEngine()
		ruleSet := RuleSet{
			Category: "", // empty
			Rules: []Rule{
				{
					ID:      "R001",
					Name:    "Test",
					Score:   50,
					Enabled: true,
					Conditions: []Condition{
						{Type: "permission", Value: "test"},
					},
				},
			},
		}

		data, _ := json.Marshal(ruleSet)
		filePath := createTempRuleFile(t, string(data))

		err := engine.LoadRulesFromFile(filePath)
		if err != nil {
			t.Fatalf("LoadRulesFromFile() error = %v", err)
		}

		rules := engine.GetRulesForCategory("default")
		if len(rules) == 0 {
			t.Error("rules should be in 'default' category")
		}
	})

	t.Run("skips invalid rules", func(t *testing.T) {
		engine := NewEngine()
		ruleSet := RuleSet{
			Category: "test",
			Rules: []Rule{
				{
					ID:      "VALID",
					Name:    "Valid Rule",
					Score:   50,
					Enabled: true,
					Conditions: []Condition{
						{Type: "permission", Value: "test"},
					},
				},
				{
					ID:         "INVALID",
					Name:       "", // invalid - empty name
					Score:      50,
					Conditions: []Condition{},
				},
			},
		}

		data, _ := json.Marshal(ruleSet)
		filePath := createTempRuleFile(t, string(data))

		err := engine.LoadRulesFromFile(filePath)
		if err != nil {
			t.Fatalf("LoadRulesFromFile() error = %v", err)
		}

		stats := engine.Stats()
		if stats.TotalRules != 1 {
			t.Errorf("expected 1 valid rule, got %d", stats.TotalRules)
		}
	})

	t.Run("replaces rules on reload", func(t *testing.T) {
		engine := NewEngine()

		// First load
		ruleSet1 := RuleSet{
			Category: "test",
			Rules: []Rule{
				{
					ID: "R001", Name: "First", Score: 50, Enabled: true,
					Conditions: []Condition{{Type: "permission", Value: "test"}},
				},
			},
		}
		data1, _ := json.Marshal(ruleSet1)
		file1 := createTempRuleFile(t, string(data1))
		engine.LoadRulesFromFile(file1)

		// Second load with same category
		ruleSet2 := RuleSet{
			Category: "test",
			Rules: []Rule{
				{
					ID: "R002", Name: "Second", Score: 60, Enabled: true,
					Conditions: []Condition{{Type: "permission", Value: "test2"}},
				},
				{
					ID: "R003", Name: "Third", Score: 70, Enabled: true,
					Conditions: []Condition{{Type: "permission", Value: "test3"}},
				},
			},
		}
		data2, _ := json.Marshal(ruleSet2)
		file2 := createTempRuleFile(t, string(data2))
		engine.LoadRulesFromFile(file2)

		// Should have only 2 rules (R002 and R003), not 3
		rules := engine.GetRulesForCategory("test")
		if len(rules) != 2 {
			t.Errorf("expected 2 rules after reload, got %d", len(rules))
		}

		// R001 should be gone
		_, found := engine.GetRuleByID("R001")
		if found {
			t.Error("R001 should have been removed after reload")
		}
	})
}

func TestEngine_LoadRulesFromDir(t *testing.T) {
	t.Run("loads all JSON files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create multiple rule files
		for i, cat := range []string{"security", "privacy"} {
			ruleSet := RuleSet{
				Category: cat,
				Rules: []Rule{
					{
						ID: cat + "_001", Name: cat + " Rule", Score: 50, Enabled: true,
						Conditions: []Condition{{Type: "permission", Value: "test"}},
					},
				},
			}
			data, _ := json.Marshal(ruleSet)
			os.WriteFile(filepath.Join(tmpDir, cat+"_rules.json"), data, 0644)
			_ = i
		}

		// Create a non-JSON file (should be ignored)
		os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("ignore me"), 0644)

		engine := NewEngine()
		err := engine.LoadRulesFromDir(tmpDir)
		if err != nil {
			t.Fatalf("LoadRulesFromDir() error = %v", err)
		}

		stats := engine.Stats()
		if stats.Categories != 2 {
			t.Errorf("expected 2 categories, got %d", stats.Categories)
		}
		if stats.TotalRules != 2 {
			t.Errorf("expected 2 rules, got %d", stats.TotalRules)
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		engine := NewEngine()
		err := engine.LoadRulesFromDir("/nonexistent/directory")
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
	})

	t.Run("skips subdirectories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create subdirectory with a JSON file
		subDir := filepath.Join(tmpDir, "subdir")
		os.MkdirAll(subDir, 0755)
		os.WriteFile(filepath.Join(subDir, "rules.json"), []byte("{}"), 0644)

		engine := NewEngine()
		engine.LoadRulesFromDir(tmpDir)

		// Should have no rules (subdir should be skipped)
		stats := engine.Stats()
		if stats.TotalRules != 0 {
			t.Errorf("expected 0 rules, got %d (subdirs should be skipped)", stats.TotalRules)
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION CONTEXT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionContext_Build(t *testing.T) {
	t.Run("builds indexes correctly", func(t *testing.T) {
		ctx := &ConditionContext{
			Permissions: []string{"perm1", "perm2"},
			APICalls:    []string{"api1", "api2"},
			Patterns:    []string{"pattern1"},
			Strings:     []string{"str1", "str2", "str3"},
			Classes:     []string{"class1"},
			Methods:     []string{"method1", "method2"},
		}

		ctx.Build()

		if !ctx.built {
			t.Error("built flag should be true")
		}

		if len(ctx.permSet) != 2 {
			t.Errorf("permSet should have 2 items, got %d", len(ctx.permSet))
		}

		if len(ctx.allValues) != 11 {
			t.Errorf("allValues should have 11 items, got %d", len(ctx.allValues))
		}
	})

	t.Run("handles empty context", func(t *testing.T) {
		ctx := &ConditionContext{}
		ctx.Build()

		if !ctx.built {
			t.Error("built flag should be true even for empty context")
		}

		if len(ctx.allValues) != 0 {
			t.Error("allValues should be empty")
		}
	})

	t.Run("double build is safe", func(t *testing.T) {
		ctx := &ConditionContext{
			Permissions: []string{"perm1"},
		}

		ctx.Build()
		ctx.Build() // should not panic or corrupt data

		if len(ctx.permSet) != 1 {
			t.Error("double build corrupted data")
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION EVALUATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestEngine_EvaluateCondition(t *testing.T) {
	engine := NewEngine()

	ctx := &ConditionContext{
		Permissions: []string{
			"android.permission.READ_SMS",
			"android.permission.INTERNET",
			"android.permission.ACCESS_FINE_LOCATION",
		},
		APICalls: []string{
			"Landroid/telephony/SmsManager;->sendTextMessage",
			"Ljava/net/URL;->openConnection",
		},
		Patterns: []string{"crypto_pattern", "network_pattern"},
		Strings:  []string{"https://api.example.com", "secret_key"},
		Classes:  []string{"com.malware.Stealer", "com.app.Main"},
		Methods:  []string{"sendData", "encrypt", "decrypt"},
	}
	ctx.Build()

	tests := []struct {
		name     string
		cond     Condition
		expected bool
	}{
		// Permission tests
		{
			name:     "permission exact match",
			cond:     Condition{Type: "permission", Value: "android.permission.READ_SMS", Exact: true},
			expected: true,
		},
		{
			name:     "permission exact no match",
			cond:     Condition{Type: "permission", Value: "android.permission.READ", Exact: true},
			expected: false,
		},
		{
			name:     "permission substring match",
			cond:     Condition{Type: "permission", Value: "READ_SMS"},
			expected: true,
		},
		{
			name:     "permission substring no match",
			cond:     Condition{Type: "permission", Value: "WRITE_SMS"},
			expected: false,
		},

		// API call tests
		{
			name:     "api_call substring match",
			cond:     Condition{Type: "api_call", Value: "SmsManager"},
			expected: true,
		},
		{
			name:     "api_call exact match",
			cond:     Condition{Type: "api_call", Value: "Landroid/telephony/SmsManager;->sendTextMessage", Exact: true},
			expected: true,
		},

		// Pattern tests
		{
			name:     "pattern match",
			cond:     Condition{Type: "pattern", Value: "crypto"},
			expected: true,
		},

		// String tests
		{
			name:     "string match",
			cond:     Condition{Type: "string", Value: "secret"},
			expected: true,
		},
		{
			name:     "string exact match",
			cond:     Condition{Type: "string", Value: "secret_key", Exact: true},
			expected: true,
		},

		// Class tests
		{
			name:     "class match",
			cond:     Condition{Type: "class", Value: "malware"},
			expected: true,
		},

		// Method tests
		{
			name:     "method match",
			cond:     Condition{Type: "method", Value: "encrypt"},
			expected: true,
		},

		// NOT operator
		{
			name:     "not operator inverts true to false",
			cond:     Condition{Type: "permission", Value: "READ_SMS", Operator: "not"},
			expected: false,
		},
		{
			name:     "not operator inverts false to true",
			cond:     Condition{Type: "permission", Value: "NONEXISTENT", Operator: "not"},
			expected: true,
		},

		// Combo tests
		{
			name:     "combo all found",
			cond:     Condition{Type: "combo", Values: []string{"READ_SMS", "SmsManager"}},
			expected: true,
		},
		{
			name:     "combo partial found",
			cond:     Condition{Type: "combo", Values: []string{"READ_SMS", "NONEXISTENT"}},
			expected: false,
		},
		{
			name:     "combo empty values",
			cond:     Condition{Type: "combo", Values: []string{}},
			expected: false,
		},
		{
			name:     "combo cross-type search",
			cond:     Condition{Type: "combo", Values: []string{"READ_SMS", "encrypt", "api.example.com"}},
			expected: true,
		},

		// Unknown type
		{
			name:     "unknown type returns false",
			cond:     Condition{Type: "unknown", Value: "test"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateCondition(tt.cond, ctx)
			if result != tt.expected {
				t.Errorf("EvaluateCondition() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE EVALUATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestEngine_EvaluateRule(t *testing.T) {
	engine := NewEngine()

	ctx := &ConditionContext{
		Permissions: []string{"perm1", "perm2", "perm3"},
		APICalls:    []string{"api1", "api2"},
	}

	tests := []struct {
		name     string
		rule     Rule
		expected bool
	}{
		{
			name: "disabled rule returns false",
			rule: Rule{
				Enabled: false,
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
				},
			},
			expected: false,
		},
		{
			name: "no conditions returns false",
			rule: Rule{
				Enabled:    true,
				Conditions: []Condition{},
			},
			expected: false,
		},
		{
			name: "AND logic all match",
			rule: Rule{
				Enabled: true,
				Logic:   "and",
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
					{Type: "permission", Value: "perm2"},
				},
			},
			expected: true,
		},
		{
			name: "AND logic one fails",
			rule: Rule{
				Enabled: true,
				Logic:   "and",
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
					{Type: "permission", Value: "nonexistent"},
				},
			},
			expected: false,
		},
		{
			name: "OR logic one matches",
			rule: Rule{
				Enabled: true,
				Logic:   "or",
				Conditions: []Condition{
					{Type: "permission", Value: "nonexistent"},
					{Type: "permission", Value: "perm1"},
				},
			},
			expected: true,
		},
		{
			name: "OR logic none match",
			rule: Rule{
				Enabled: true,
				Logic:   "or",
				Conditions: []Condition{
					{Type: "permission", Value: "nonexistent1"},
					{Type: "permission", Value: "nonexistent2"},
				},
			},
			expected: false,
		},
		{
			name: "threshold met",
			rule: Rule{
				Enabled:  true,
				Logic:    "threshold",
				MinMatch: 2,
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
					{Type: "permission", Value: "perm2"},
					{Type: "permission", Value: "nonexistent"},
				},
			},
			expected: true,
		},
		{
			name: "threshold not met",
			rule: Rule{
				Enabled:  true,
				Logic:    "threshold",
				MinMatch: 3,
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
					{Type: "permission", Value: "perm2"},
					{Type: "permission", Value: "nonexistent"},
				},
			},
			expected: false,
		},
		{
			name: "default logic is AND",
			rule: Rule{
				Enabled: true,
				Logic:   "", // empty = default = and
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
					{Type: "permission", Value: "perm2"},
				},
			},
			expected: true,
		},
		{
			name: "unknown logic returns false",
			rule: Rule{
				Enabled: true,
				Logic:   "xor", // unknown
				Conditions: []Condition{
					{Type: "permission", Value: "perm1"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateRule(tt.rule, ctx)
			if result != tt.expected {
				t.Errorf("EvaluateRule() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestEngine_EvaluateAll(t *testing.T) {
	engine := NewEngine()

	// Load rules
	ruleSet := RuleSet{
		Category: "test",
		Rules: []Rule{
			{
				ID: "R001", Name: "SMS Rule", Score: 80, Severity: "high", Enabled: true,
				Description: "Detects SMS access",
				Conditions:  []Condition{{Type: "permission", Value: "READ_SMS"}},
			},
			{
				ID: "R002", Name: "Network Rule", Score: 60, Severity: "medium", Enabled: true,
				Description: "Detects network access",
				Conditions:  []Condition{{Type: "permission", Value: "INTERNET"}},
			},
			{
				ID: "R003", Name: "Disabled Rule", Score: 100, Enabled: false,
				Conditions: []Condition{{Type: "permission", Value: "READ_SMS"}},
			},
		},
	}

	data, _ := json.Marshal(ruleSet)
	filePath := createTempRuleFile(t, string(data))
	engine.LoadRulesFromFile(filePath)

	ctx := &ConditionContext{
		Permissions: []string{"android.permission.READ_SMS"},
	}

	results := engine.EvaluateAll(ctx)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.RuleID != "R001" {
		t.Errorf("expected R001, got %s", r.RuleID)
	}
	if r.Score != 80 {
		t.Errorf("expected score 80, got %d", r.Score)
	}
	if !r.Matched {
		t.Error("Matched should be true")
	}
	if !r.IsCritical() && r.Severity == "critical" {
		t.Error("IsCritical() incorrect")
	}
	if !r.IsHighOrAbove() {
		t.Error("IsHighOrAbove() should be true for 'high' severity")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUERY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestEngine_GetRulesForCategory(t *testing.T) {
	engine := NewEngine()
	ruleSet := createTestRuleSet()

	data, _ := json.Marshal(ruleSet)
	filePath := createTempRuleFile(t, string(data))
	engine.LoadRulesFromFile(filePath)

	t.Run("existing category", func(t *testing.T) {
		rules := engine.GetRulesForCategory("test")
		if len(rules) != 2 {
			t.Errorf("expected 2 rules, got %d", len(rules))
		}
	})

	t.Run("nonexistent category", func(t *testing.T) {
		rules := engine.GetRulesForCategory("nonexistent")
		if rules != nil {
			t.Error("expected nil for nonexistent category")
		}
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		rules := engine.GetRulesForCategory("test")
		originalName := rules[0].Name
		rules[0].Name = "Modified"

		rules2 := engine.GetRulesForCategory("test")
		if rules2[0].Name != originalName {
			t.Error("GetRulesForCategory should return a copy")
		}
	})
}

func TestEngine_GetRuleByID(t *testing.T) {
	engine := NewEngine()
	ruleSet := createTestRuleSet()

	data, _ := json.Marshal(ruleSet)
	filePath := createTempRuleFile(t, string(data))
	engine.LoadRulesFromFile(filePath)

	t.Run("existing rule", func(t *testing.T) {
		rule, found := engine.GetRuleByID("TEST001")
		if !found {
			t.Fatal("expected to find rule TEST001")
		}
		if rule.Name != "Test Rule 1" {
			t.Errorf("expected 'Test Rule 1', got %q", rule.Name)
		}
	})

	t.Run("nonexistent rule", func(t *testing.T) {
		_, found := engine.GetRuleByID("NONEXISTENT")
		if found {
			t.Error("should not find nonexistent rule")
		}
	})
}

func TestEngine_GetAllRules(t *testing.T) {
	engine := NewEngine()

	// Load multiple categories
	for _, cat := range []string{"cat1", "cat2"} {
		ruleSet := RuleSet{
			Category: cat,
			Rules: []Rule{
				{
					ID: cat + "_001", Name: cat + " Rule", Score: 50, Enabled: true,
					Conditions: []Condition{{Type: "permission", Value: "test"}},
				},
			},
		}
		data, _ := json.Marshal(ruleSet)
		filePath := createTempRuleFile(t, string(data))
		engine.LoadRulesFromFile(filePath)
	}

	allRules := engine.GetAllRules()

	if len(allRules) != 2 {
		t.Errorf("expected 2 categories, got %d", len(allRules))
	}

	// Check it's a copy
	if rules, ok := allRules["cat1"]; ok {
		rules[0].Name = "Modified"

		allRules2 := engine.GetAllRules()
		if allRules2["cat1"][0].Name == "Modified" {
			t.Error("GetAllRules should return defensive copy")
		}
	}
}

func TestEngine_Stats(t *testing.T) {
	engine := NewEngine()

	ruleSet := RuleSet{
		Category: "test",
		Rules: []Rule{
			{ID: "R001", Name: "Enabled 1", Score: 50, Enabled: true,
				Conditions: []Condition{{Type: "permission", Value: "test"}}},
			{ID: "R002", Name: "Enabled 2", Score: 50, Enabled: true,
				Conditions: []Condition{{Type: "permission", Value: "test"}}},
			{ID: "R003", Name: "Disabled", Score: 50, Enabled: false,
				Conditions: []Condition{{Type: "permission", Value: "test"}}},
		},
	}

	data, _ := json.Marshal(ruleSet)
	filePath := createTempRuleFile(t, string(data))
	engine.LoadRulesFromFile(filePath)

	stats := engine.Stats()

	if stats.Categories != 1 {
		t.Errorf("expected 1 category, got %d", stats.Categories)
	}
	if stats.TotalRules != 3 {
		t.Errorf("expected 3 total rules, got %d", stats.TotalRules)
	}
	if stats.EnabledRules != 2 {
		t.Errorf("expected 2 enabled rules, got %d", stats.EnabledRules)
	}
	if stats.DisabledRules != 1 {
		t.Errorf("expected 1 disabled rule, got %d", stats.DisabledRules)
	}

	// Test String()
	str := stats.String()
	if !strings.Contains(str, "3 total") {
		t.Errorf("Stats.String() should contain '3 total', got %q", str)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE EVALUATION RESULT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestRuleEvaluationResult_IsCritical(t *testing.T) {
	tests := []struct {
		severity string
		expected bool
	}{
		{"critical", true},
		{"high", false},
		{"medium", false},
		{"low", false},
		{"info", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			r := RuleEvaluationResult{Severity: tt.severity}
			if r.IsCritical() != tt.expected {
				t.Errorf("IsCritical() = %v, expected %v", r.IsCritical(), tt.expected)
			}
		})
	}
}

func TestRuleEvaluationResult_IsHighOrAbove(t *testing.T) {
	tests := []struct {
		severity string
		expected bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", false},
		{"low", false},
		{"info", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			r := RuleEvaluationResult{Severity: tt.severity}
			if r.IsHighOrAbove() != tt.expected {
				t.Errorf("IsHighOrAbove() = %v, expected %v", r.IsHighOrAbove(), tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildSet(t *testing.T) {
	t.Run("normal slice", func(t *testing.T) {
		set := buildSet([]string{"a", "b", "c"})
		if len(set) != 3 {
			t.Errorf("expected 3, got %d", len(set))
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		set := buildSet([]string{})
		if set != nil {
			t.Error("expected nil for empty slice")
		}
	})

	t.Run("nil slice", func(t *testing.T) {
		set := buildSet(nil)
		if set != nil {
			t.Error("expected nil for nil slice")
		}
	})

	t.Run("duplicates", func(t *testing.T) {
		set := buildSet([]string{"a", "a", "b"})
		if len(set) != 2 {
			t.Errorf("expected 2 unique items, got %d", len(set))
		}
	})
}

func TestContainsExact(t *testing.T) {
	set := map[string]struct{}{
		"apple":  {},
		"banana": {},
	}

	if !containsExact(set, "apple") {
		t.Error("should find 'apple'")
	}
	if containsExact(set, "orange") {
		t.Error("should not find 'orange'")
	}
	if containsExact(nil, "apple") {
		t.Error("nil set should return false")
	}
}

func TestContainsSubstring(t *testing.T) {
	items := []string{"hello world", "foo bar", "test123"}

	if !containsSubstring(items, "world") {
		t.Error("should find 'world'")
	}
	if !containsSubstring(items, "123") {
		t.Error("should find '123'")
	}
	if containsSubstring(items, "notfound") {
		t.Error("should not find 'notfound'")
	}
	if containsSubstring(nil, "test") {
		t.Error("nil slice should return false")
	}
	if containsSubstring([]string{}, "test") {
		t.Error("empty slice should return false")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkEngine_EvaluateCondition(b *testing.B) {
	engine := NewEngine()
	ctx := &ConditionContext{
		Permissions: make([]string, 100),
		APICalls:    make([]string, 100),
	}
	for i := 0; i < 100; i++ {
		ctx.Permissions[i] = "permission_" + string(rune('A'+i%26))
		ctx.APICalls[i] = "api_call_" + string(rune('A'+i%26))
	}
	ctx.Build()

	cond := Condition{Type: "permission", Value: "permission_M", Exact: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateCondition(cond, ctx)
	}
}

func BenchmarkEngine_EvaluateAll(b *testing.B) {
	engine := NewEngine()

	// Create 100 rules
	rules := make([]Rule, 100)
	for i := 0; i < 100; i++ {
		rules[i] = Rule{
			ID:    "R" + string(rune('0'+i/10)) + string(rune('0'+i%10)),
			Name:  "Rule " + string(rune('0'+i)),
			Score: 50, Enabled: true,
			Conditions: []Condition{
				{Type: "permission", Value: "perm_" + string(rune('A'+i%26))},
			},
		}
	}

	ruleSet := RuleSet{Category: "bench", Rules: rules}
	data, _ := json.Marshal(ruleSet)

	tmpDir := b.TempDir()
	filePath := filepath.Join(tmpDir, "rules.json")
	os.WriteFile(filePath, data, 0644)
	engine.LoadRulesFromFile(filePath)

	ctx := &ConditionContext{
		Permissions: []string{"perm_A", "perm_B", "perm_C", "perm_D", "perm_E"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateAll(ctx)
	}
}

func BenchmarkConditionContext_Build(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ctx := &ConditionContext{
			Permissions: make([]string, 50),
			APICalls:    make([]string, 200),
			Patterns:    make([]string, 100),
			Strings:     make([]string, 500),
			Classes:     make([]string, 300),
			Methods:     make([]string, 1000),
		}
		ctx.Build()
	}
}
