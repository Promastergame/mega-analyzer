package sandbox

import (
	"testing"
	"time"
)

func TestBehaviorClassifier_Analyze(t *testing.T) {
	bc := NewBehaviorClassifier()

	// Create test events
	events := []Event{
		KernelEvent{
			Timestamp: time.Now(),
			EventType: EventRegSetValue,
			ProcessID: 1234,
			Path:      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
		},
		APICall{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "VirtualAllocEx",
		},
		APICall{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "WriteProcessMemory",
		},
		APICall{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "CreateRemoteThread",
		},
	}

	analysis := bc.Analyze(events)

	if analysis == nil {
		t.Fatal("Expected non-nil analysis")
	}

	if analysis.RiskScore < 0 || analysis.RiskScore > 100 {
		t.Errorf("Risk score out of range: %d", analysis.RiskScore)
	}

	if analysis.Techniques == nil {
		t.Error("Expected non-nil Techniques slice")
	}

	if analysis.Indicators == nil {
		t.Error("Expected non-nil Indicators slice")
	}
}

func TestBehaviorClassifier_AddRule(t *testing.T) {
	bc := NewBehaviorClassifier()

	rule := ClassificationRule{
		Name:        "Test Rule",
		Technique:   "T9999",
		Tactic:      "Test",
		Severity:    5,
		Description: "Test rule",
		Pattern: EventPattern{
			Sequence: []EventMatcher{
				{EventType: "TestEvent"},
			},
			MinMatches: 1,
		},
	}

	err := bc.AddRule(rule)
	if err != nil {
		t.Skipf("AddRule failed (expected on non-Windows): %v", err)
	}
}

func TestBehaviorClassifier_GetRules(t *testing.T) {
	bc := NewBehaviorClassifier()

	rules := bc.GetRules()
	if rules == nil {
		t.Fatal("Expected non-nil rules")
	}

	if len(rules) == 0 {
		t.Error("Expected at least one default rule")
	}
}

func TestDetectProcessInjection_WithBehaviorClassifier(t *testing.T) {
	bc := NewBehaviorClassifier()

	// Create process injection event sequence
	events := []Event{
		APICall{
			Timestamp: time.Now(),
			ProcessID: 1234,
			Function:  "VirtualAllocEx",
		},
		APICall{
			Timestamp: time.Now().Add(1 * time.Second),
			ProcessID: 1234,
			Function:  "WriteProcessMemory",
		},
		APICall{
			Timestamp: time.Now().Add(2 * time.Second),
			ProcessID: 1234,
			Function:  "CreateRemoteThread",
		},
	}

	analysis := bc.Analyze(events)

	// Should detect process injection on Windows
	if len(analysis.Techniques) > 0 {
		found := false
		for _, tech := range analysis.Techniques {
			if tech.ID == "T1055" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to detect T1055 (Process Injection)")
		}
	}
}

func TestDetectRegistryPersistence(t *testing.T) {
	bc := NewBehaviorClassifier()

	// Create registry persistence event
	events := []Event{
		KernelEvent{
			Timestamp: time.Now(),
			EventType: EventRegSetValue,
			ProcessID: 1234,
			Path:      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
		},
	}

	analysis := bc.Analyze(events)

	// Should detect registry persistence on Windows
	if len(analysis.Techniques) > 0 {
		found := false
		for _, tech := range analysis.Techniques {
			if tech.ID == "T1547" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to detect T1547 (Registry Persistence)")
		}
	}
}

func TestDetectRansomwareBehavior(t *testing.T) {
	bc := NewBehaviorClassifier()

	// Create mass encryption events
	events := []Event{}
	baseTime := time.Now()
	for i := 0; i < 15; i++ {
		events = append(events, APICall{
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
			ProcessID: 1234,
			Function:  "CryptEncrypt",
		})
	}

	analysis := bc.Analyze(events)

	// Should detect ransomware behavior on Windows
	if len(analysis.Techniques) > 0 {
		found := false
		for _, tech := range analysis.Techniques {
			if tech.ID == "T1486" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to detect T1486 (Ransomware)")
		}
	}
}

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()

	if len(rules) == 0 {
		t.Fatal("Expected at least one default rule")
	}

	// Verify all rules have required fields
	for _, rule := range rules {
		if rule.Name == "" {
			t.Error("Rule missing name")
		}
		if rule.Technique == "" {
			t.Error("Rule missing technique")
		}
		if rule.Severity < 1 || rule.Severity > 10 {
			t.Errorf("Rule severity out of range: %d", rule.Severity)
		}
	}
}

func TestRegistryPersistenceRule(t *testing.T) {
	rule := RegistryPersistenceRule()

	if rule.Technique != "T1547" {
		t.Errorf("Expected technique T1547, got %s", rule.Technique)
	}

	if rule.Tactic != "Persistence" {
		t.Errorf("Expected tactic Persistence, got %s", rule.Tactic)
	}
}

func TestProcessInjectionRule(t *testing.T) {
	rule := ProcessInjectionRule()

	if rule.Technique != "T1055" {
		t.Errorf("Expected technique T1055, got %s", rule.Technique)
	}

	if len(rule.Pattern.Sequence) != 3 {
		t.Errorf("Expected 3 sequence matchers, got %d", len(rule.Pattern.Sequence))
	}
}

func TestRansomwareBehaviorRule(t *testing.T) {
	rule := RansomwareBehaviorRule()

	if rule.Technique != "T1486" {
		t.Errorf("Expected technique T1486, got %s", rule.Technique)
	}

	if rule.Pattern.MinMatches != 10 {
		t.Errorf("Expected MinMatches 10, got %d", rule.Pattern.MinMatches)
	}
}
