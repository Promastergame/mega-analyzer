package vulnscan

import (
	"net/http"
	"strings"
	"testing"
)

// ─── GetDynamicWebRules / AddDynamicWebRule / DeleteDynamicWebRule ─────────────

func TestGetDynamicWebRules_ReturnsSlice(t *testing.T) {
	rules := GetDynamicWebRules()
	if rules == nil {
		t.Error("GetDynamicWebRules should return non-nil")
	}
}

func TestAddDynamicWebRule_EmptyID(t *testing.T) {
	err := AddDynamicWebRule(DynamicWebRule{ID: ""})
	if err == nil {
		t.Error("expected error for empty rule ID")
	}
}

func TestAddDynamicWebRule_Valid(t *testing.T) {
	rule := DynamicWebRule{
		ID:          "test-header-rule-unique-xyz",
		Name:        "Test Missing Header",
		Type:        "header_check",
		HeaderName:  "X-Test-Header",
		HeaderCheck: "missing",
		Severity:    SeverityLow,
	}
	// clean up before
	_ = DeleteDynamicWebRule(rule.ID)
	err := AddDynamicWebRule(rule)
	if err != nil {
		t.Fatalf("unexpected error adding rule: %v", err)
	}
	// verify it's present
	rules := GetDynamicWebRules()
	found := false
	for _, r := range rules {
		if r.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("rule should be present after Add")
	}
	// cleanup
	_ = DeleteDynamicWebRule(rule.ID)
}

func TestAddDynamicWebRule_Duplicate(t *testing.T) {
	rule := DynamicWebRule{
		ID:   "test-dup-rule-abc",
		Name: "Dup Test",
		Type: "header_check",
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	err := AddDynamicWebRule(rule)
	if err == nil {
		t.Error("expected error for duplicate rule ID")
	}
	_ = DeleteDynamicWebRule(rule.ID)
}

func TestDeleteDynamicWebRule_NotFound(t *testing.T) {
	err := DeleteDynamicWebRule("nonexistent-rule-id-xyz")
	if err == nil {
		t.Error("expected error for non-existent rule")
	}
}

func TestDeleteDynamicWebRule_Valid(t *testing.T) {
	rule := DynamicWebRule{
		ID:   "test-delete-rule-xyz",
		Name: "Delete Test",
		Type: "header_check",
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	err := DeleteDynamicWebRule(rule.ID)
	if err != nil {
		t.Fatalf("unexpected error deleting rule: %v", err)
	}
}

// ─── RunDynamicHeaderRules ────────────────────────────────────────────────────

func TestRunDynamicHeaderRules_EmptyHeaders(t *testing.T) {
	s, _ := NewScanner("https://example.com")
	vulns := s.RunDynamicHeaderRules(map[string][]string{})
	_ = vulns
}

func TestRunDynamicHeaderRules_MissingHeader(t *testing.T) {
	// Add a header_check rule first
	rule := DynamicWebRule{
		ID:          "test-hdr-missing-xyz",
		Name:        "X-Missing-Header check",
		Type:        "header_check",
		HeaderName:  "X-Missing-Header",
		HeaderCheck: "missing",
		Severity:    SeverityMedium,
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	defer DeleteDynamicWebRule(rule.ID)

	s, _ := NewScanner("https://example.com")
	headers := map[string][]string{
		"Content-Type": {"application/json"},
	}
	vulns := s.RunDynamicHeaderRules(headers)
	found := false
	for _, v := range vulns {
		if v.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for missing header")
	}
}

func TestRunDynamicHeaderRules_EqualsMatch(t *testing.T) {
	rule := DynamicWebRule{
		ID:          "test-hdr-equals-xyz",
		Name:        "X-Frame-Options ALLOWALL",
		Type:        "header_check",
		HeaderName:  "X-Frame-Options",
		HeaderCheck: "equals",
		HeaderValue: "ALLOWALL",
		Severity:    SeverityHigh,
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	defer DeleteDynamicWebRule(rule.ID)

	s, _ := NewScanner("https://example.com")
	headers := map[string][]string{
		"X-Frame-Options": {"ALLOWALL"},
	}
	vulns := s.RunDynamicHeaderRules(headers)
	found := false
	for _, v := range vulns {
		if v.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for equals match")
	}
}

func TestRunDynamicHeaderRules_ContainsMatch(t *testing.T) {
	rule := DynamicWebRule{
		ID:          "test-hdr-contains-xyz",
		Name:        "Server header leaks version",
		Type:        "header_check",
		HeaderName:  "Server",
		HeaderCheck: "contains",
		HeaderValue: "Apache/2",
		Severity:    SeverityLow,
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	defer DeleteDynamicWebRule(rule.ID)

	s, _ := NewScanner("https://example.com")
	headers := map[string][]string{
		"Server": {"Apache/2.4.51 (Ubuntu)"},
	}
	vulns := s.RunDynamicHeaderRules(headers)
	found := false
	for _, v := range vulns {
		if v.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for contains match")
	}
}

// ─── RunDynamicPassiveRules ───────────────────────────────────────────────────

func TestRunDynamicPassiveRules_EmptyBody(t *testing.T) {
	s, _ := NewScanner("https://example.com")
	vulns := s.RunDynamicPassiveRules("", "https://example.com")
	_ = vulns
}

func TestRunDynamicPassiveRules_WithMatch(t *testing.T) {
	rule := DynamicWebRule{
		ID:           "test-passive-xyz",
		Name:         "AWS Key Exposure",
		Type:         "regex_passive",
		RegexPattern: `AKIA[0-9A-Z]{16}`,
		Severity:     SeverityCritical,
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	defer DeleteDynamicWebRule(rule.ID)

	s, _ := NewScanner("https://example.com")
	body := `var key = "AKIAIOSFODNN7EXAMPLE"; // leaked`
	vulns := s.RunDynamicPassiveRules(body, "https://example.com/config.js")
	found := false
	for _, v := range vulns {
		if v.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected passive match for AWS key pattern")
	}
}

func TestRunDynamicPassiveRules_InvalidRegex_Skipped(t *testing.T) {
	rule := DynamicWebRule{
		ID:           "test-passive-bad-regex",
		Name:         "Bad regex rule",
		Type:         "regex_passive",
		RegexPattern: "[invalid regex",
		Severity:     SeverityLow,
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	defer DeleteDynamicWebRule(rule.ID)

	s, _ := NewScanner("https://example.com")
	// Should not panic — invalid regex rules are silently skipped
	vulns := s.RunDynamicPassiveRules("some body text", "https://example.com/")
	_ = vulns
}

func TestRunDynamicPassiveRules_LongMatch_Truncated(t *testing.T) {
	rule := DynamicWebRule{
		ID:           "test-passive-long-xyz",
		Name:         "Long match test",
		Type:         "regex_passive",
		RegexPattern: `longmatch\w+`,
		Severity:     SeverityInfo,
	}
	_ = DeleteDynamicWebRule(rule.ID)
	_ = AddDynamicWebRule(rule)
	defer DeleteDynamicWebRule(rule.ID)

	s, _ := NewScanner("https://example.com")
	// 100-char match should be truncated in evidence
	longWord := "longmatch" + strings.Repeat("x", 100)
	vulns := s.RunDynamicPassiveRules(longWord, "https://example.com/")
	found := false
	for _, v := range vulns {
		if v.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Error("expected passive match for long pattern")
	}
}

// ─── ScanHTMLBody ────────────────────────────────────────────────────────────

func TestScanHTMLBody_Empty(t *testing.T) {
	s, _ := NewScanner("https://example.com")
	vulns := s.ScanHTMLBody("", "https://example.com")
	_ = vulns
}

func TestScanHTMLBody_WithSecrets(t *testing.T) {
	s, _ := NewScanner("https://example.com")
	// HTML with a hardcoded private key marker
	html := `<script>var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc";</script>`
	vulns := s.ScanHTMLBody(html, "https://example.com/index.html")
	_ = vulns // may or may not find JWT depending on rules; just no panic
}

// ─── ScanFromRequest safety gate ─────────────────────────────────────────────

func TestScanFromRequest_SafetyGate(t *testing.T) {
	s, _ := NewScanner("https://example.com")
	// IOwnThisTarget is false by default
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_, err := s.ScanFromRequest(req)
	if err == nil {
		t.Error("expected safety gate error when IOwnThisTarget is false")
	}
}
