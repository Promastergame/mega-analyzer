package vulnscan

import (
	"mega-analyzer/pkg/internal/appconfig"

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ruleRegexCache memoizes compiled patterns from dynamic rules. Rule patterns
// come from user JSON config so they cannot be package-level constants, but
// recompiling them for every form/response is wasteful. A nil value records a
// pattern that failed to compile so it is not retried.
var (
	ruleRegexCache   = make(map[string]*regexp.Regexp)
	ruleRegexCacheMu sync.Mutex
)

// cachedRuleRegex compiles pattern once and returns the cached result on
// every subsequent call. The boolean is false for invalid patterns.
func cachedRuleRegex(pattern string) (*regexp.Regexp, bool) {
	ruleRegexCacheMu.Lock()
	defer ruleRegexCacheMu.Unlock()
	if re, ok := ruleRegexCache[pattern]; ok {
		return re, re != nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		ruleRegexCache[pattern] = nil
		return nil, false
	}
	ruleRegexCache[pattern] = re
	return re, true
}

type DynamicWebRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Mitigation  string   `json:"mitigation"`
	Type        string   `json:"type"` // "fuzz", "regex_passive", "header_check"

	// For fuzz rules
	Payloads   []string `json:"payloads,omitempty"`
	MatchType  string   `json:"match_type,omitempty"`  // "contains", "regex", "sql_error", "lfi_success", "status_code"
	MatchValue string   `json:"match_value,omitempty"` // used for "contains", "regex" (pattern), "status_code" (int)

	// For regex_passive rules
	RegexPattern string `json:"regex_pattern,omitempty"`

	// For header_check rules
	HeaderName  string `json:"header_name,omitempty"`
	HeaderCheck string `json:"header_check,omitempty"` // "missing", "contains", "equals"
	HeaderValue string `json:"header_value,omitempty"`
}

// RunDynamicHeaderRules performs HTTP header security checks based on dynamic rules
func (s *Scanner) RunDynamicHeaderRules(headers map[string][]string) []Vulnerability {
	var list []Vulnerability
	rules := GetDynamicWebRules()

	for _, rule := range rules {
		if rule.Type != "header_check" {
			continue
		}

		val := headers[rule.HeaderName]
		triggered := false

		switch rule.HeaderCheck {
		case "missing":
			if len(val) == 0 || val[0] == "" {
				triggered = true
			}
		case "equals":
			if len(val) > 0 && val[0] == rule.HeaderValue {
				triggered = true
			}
		case "contains":
			if len(val) > 0 && strings.Contains(val[0], rule.HeaderValue) {
				triggered = true
			}
		}

		if triggered {
			list = append(list, Vulnerability{
				ID:          rule.ID,
				Name:        rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				URL:         s.Target,
				Mitigation:  rule.Mitigation,
			})
		}
	}
	return list
}

// RunDynamicPassiveRules checks the body against dynamic passive regex rules
func (s *Scanner) RunDynamicPassiveRules(body string, targetUrl string) []Vulnerability {
	var list []Vulnerability
	rules := GetDynamicWebRules()

	for _, rule := range rules {
		if rule.Type != "regex_passive" || rule.RegexPattern == "" {
			continue
		}

		re, ok := cachedRuleRegex(rule.RegexPattern)
		if !ok {
			continue
		}

		matches := re.FindAllString(body, -1)

		// Deduplicate matches
		uniqueMatches := make(map[string]bool)
		for _, m := range matches {
			uniqueMatches[m] = true
		}

		for m := range uniqueMatches {
			evidence := m
			if len(evidence) > 80 {
				evidence = evidence[:80] + "..."
			}

			list = append(list, Vulnerability{
				ID:          rule.ID,
				Name:        rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				URL:         targetUrl,
				Evidence:    fmt.Sprintf("Passive match: %s", evidence),
				Mitigation:  rule.Mitigation,
			})
		}
	}
	return list
}

// RunDynamicFuzzRules runs active dynamic payloads on input fields in the crawled HTML forms
func (s *Scanner) RunDynamicFuzzRules(form Form) []Vulnerability {
	var list []Vulnerability
	rules := GetDynamicWebRules()

	for _, rule := range rules {
		if rule.Type != "fuzz" || len(rule.Payloads) == 0 {
			continue
		}

		for _, input := range form.Inputs {
			for _, payload := range rule.Payloads {
				body, _, statuses := s.sendFuzzRequest(form, input, payload)

				triggered := false
				evidence := ""

				switch rule.MatchType {
				case "contains":
					matchVal := rule.MatchValue
					if matchVal == "" {
						matchVal = payload
					}
					if strings.Contains(body, matchVal) {
						triggered = true
						evidence = fmt.Sprintf("Response contains string: %s", matchVal)
					}
				case "regex":
					if rule.MatchValue != "" {
						if re, ok := cachedRuleRegex(rule.MatchValue); ok && re.MatchString(body) {
							triggered = true
							evidence = fmt.Sprintf("Response matched pattern: %s", rule.MatchValue)
						}
					}
				case "status_code":
					expectedCode := rule.MatchValue
					for _, code := range statuses {
						if fmt.Sprintf("%d", code) == expectedCode {
							triggered = true
							evidence = fmt.Sprintf("Status code returned: %d", code)
							break
						}
					}
				case "sql_error":
					sqlErrors := []string{
						"SQL syntax", "sqlite3.OperationalError", "unclosed quotation mark",
						"database error", "PostgreSQL query failed", "SQLITE_ERROR",
					}
					for _, sqlErr := range sqlErrors {
						if strings.Contains(strings.ToLower(body), strings.ToLower(sqlErr)) {
							triggered = true
							evidence = fmt.Sprintf("Database error detected: %s", sqlErr)
							break
						}
					}
				case "lfi_success":
					if strings.Contains(body, "root:x:0:0") || strings.Contains(strings.ToLower(body), "[extensions]") || strings.Contains(strings.ToLower(body), "[fonts]") {
						triggered = true
						evidence = "Read server system file successfully."
					}
				}

				if triggered {
					list = append(list, Vulnerability{
						ID:          rule.ID,
						Name:        rule.Name,
						Description: rule.Description,
						Severity:    rule.Severity,
						URL:         form.Action,
						Parameter:   input,
						Evidence:    evidence,
						Payload:     payload,
						Mitigation:  rule.Mitigation,
					})
					break // exit payload loop for this input once matched
				}
			}
		}
	}
	return list
}

var (
	dynamicWebRules    []DynamicWebRule
	dynamicWebMutex    sync.RWMutex
	dynamicWebFilePath = appconfig.Path("configs/dynamic_rules/web_rules.json")
)

func init() {
	_ = LoadDynamicWebRules()
}

// LoadDynamicWebRules loads rules from the JSON storage file
func LoadDynamicWebRules() error {
	dynamicWebMutex.Lock()
	defer dynamicWebMutex.Unlock()

	dir := filepath.Dir(dynamicWebFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if _, err := os.Stat(dynamicWebFilePath); os.IsNotExist(err) {
		emptyBytes, _ := json.MarshalIndent([]DynamicWebRule{}, "", "  ")
		_ = os.WriteFile(dynamicWebFilePath, emptyBytes, 0644)
		dynamicWebRules = []DynamicWebRule{}
		return nil
	}

	data, err := os.ReadFile(dynamicWebFilePath)
	if err != nil {
		return err
	}

	var rules []DynamicWebRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	dynamicWebRules = rules
	return nil
}

// SaveDynamicWebRules saves rules to the JSON storage file
func SaveDynamicWebRules() error {
	dynamicWebMutex.RLock()
	defer dynamicWebMutex.RUnlock()

	dir := filepath.Dir(dynamicWebFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(dynamicWebRules, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dynamicWebFilePath, data, 0644)
}

// GetDynamicWebRules returns all active rules
func GetDynamicWebRules() []DynamicWebRule {
	dynamicWebMutex.RLock()
	defer dynamicWebMutex.RUnlock()

	copied := make([]DynamicWebRule, len(dynamicWebRules))
	copy(copied, dynamicWebRules)
	return copied
}

// AddDynamicWebRule adds a new rule
func AddDynamicWebRule(rule DynamicWebRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	dynamicWebMutex.Lock()
	for _, r := range dynamicWebRules {
		if r.ID == rule.ID {
			dynamicWebMutex.Unlock()
			return fmt.Errorf("rule with ID %s already exists", rule.ID)
		}
	}

	dynamicWebRules = append(dynamicWebRules, rule)
	dynamicWebMutex.Unlock()

	return SaveDynamicWebRules()
}

// UpdateDynamicWebRule updates an existing rule
func UpdateDynamicWebRule(id string, rule DynamicWebRule) error {
	dynamicWebMutex.Lock()
	found := false
	for i, r := range dynamicWebRules {
		if r.ID == id {
			dynamicWebRules[i] = rule
			found = true
			break
		}
	}
	dynamicWebMutex.Unlock()

	if !found {
		return fmt.Errorf("rule with ID %s not found", id)
	}

	return SaveDynamicWebRules()
}

// DeleteDynamicWebRule deletes a rule by ID
func DeleteDynamicWebRule(id string) error {
	dynamicWebMutex.Lock()
	index := -1
	for i, r := range dynamicWebRules {
		if r.ID == id {
			index = i
			break
		}
	}

	if index == -1 {
		dynamicWebMutex.Unlock()
		return fmt.Errorf("rule with ID %s not found", id)
	}

	dynamicWebRules = append(dynamicWebRules[:index], dynamicWebRules[index+1:]...)
	dynamicWebMutex.Unlock()

	return SaveDynamicWebRules()
}
