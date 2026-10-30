package ml

import (
	"testing"
)

func TestGetAllCurrencyTimePatterns(t *testing.T) {
	patterns := GetAllCurrencyTimePatterns()
	if len(patterns) == 0 {
		t.Error("GetAllCurrencyTimePatterns() returned no patterns")
	}

	// Check if all patterns have unique IDs
	ids := make(map[string]bool)
	for _, p := range patterns {
		if p.ID == "" {
			t.Errorf("Pattern with description %q has no ID", p.Description)
		}
		if ids[p.ID] {
			t.Errorf("Duplicate pattern ID: %s", p.ID)
		}
		ids[p.ID] = true
	}
}

func TestCurrencyTimePatterns_MatchSpecific(t *testing.T) {
	// Test case for CURRENCY_GETTER
	matched := false
	for _, p := range CurrencyTimePatterns {
		if p.ID == "CURRENCY_GETTER" {
			for _, m := range p.MethodNames {
				if m == "getcoins" {
					matched = true
					break
				}
			}
		}
	}
	if !matched {
		t.Error("CURRENCY_GETTER should include 'getcoins'")
	}
}
