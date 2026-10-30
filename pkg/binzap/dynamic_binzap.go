package binzap

import (
	"mega-analyzer/pkg/internal/appconfig"

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"mega-analyzer/pkg/binzap/lex"
)

// PatternStep is one step of a user-defined bytecode matcher.
type PatternStep struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// validStepTypes enumerates the supported dynamic matcher step kinds.
var validStepTypes = map[string]bool{
	"opcode": true, "any_register": true, "string_contains": true,
	"string_equals": true, "any_method_ref": true, "method_ref_contains": true,
}

type DynamicBinzapRule struct {
	IDStr       string        `json:"id"`
	NameStr     string        `json:"name"`
	SeverityVal Severity      `json:"severity"`
	Steps       []PatternStep `json:"pattern_steps"`
}

func (r *DynamicBinzapRule) ID() string         { return r.IDStr }
func (r *DynamicBinzapRule) Name() string       { return r.NameStr }
func (r *DynamicBinzapRule) Severity() Severity { return r.SeverityVal }

func (r *DynamicBinzapRule) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	if len(r.Steps) == 0 {
		return findings
	}

	pattern := make(lex.Pattern, len(r.Steps))
	for i, step := range r.Steps {
		switch step.Type {
		case "opcode":
			pattern[i] = lex.Opcode(step.Value)
		case "any_register":
			pattern[i] = lex.AnyRegister()
		case "string_contains":
			pattern[i] = lex.StringContains(step.Value)
		case "string_equals":
			pattern[i] = lex.StringEquals(step.Value)
		case "any_method_ref":
			pattern[i] = lex.AnyMethodRef()
		case "method_ref_contains":
			pattern[i] = lex.MethodRefContains(step.Value)
		default:
			pattern[i] = func(t lex.Token) bool { return false }
		}
	}

	for _, idx := range lex.Match(tokens, pattern) {
		var parts []string
		for k := 0; k < len(r.Steps) && idx+k < len(tokens); k++ {
			parts = append(parts, tokens[idx+k].Value)
		}
		findings = append(findings, Finding{
			RuleID:     r.ID(),
			RuleName:   r.Name(),
			Severity:   r.Severity(),
			Message:    fmt.Sprintf("Dynamic match: %s", r.Name()),
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Column:     tokens[idx].Column,
			Evidence:   strings.Join(parts, " "),
			Confidence: ConfidenceHigh,
			Category:   "custom-rule",
		})
	}
	return findings
}

// Validate performs static validation of a dynamic rule definition.
func (r *DynamicBinzapRule) Validate() error {
	if strings.TrimSpace(r.IDStr) == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}
	for i, s := range r.Steps {
		if !validStepTypes[s.Type] {
			return fmt.Errorf("rule %s: step %d has unknown type %q", r.IDStr, i, s.Type)
		}
	}
	return nil
}

var (
	dynamicBinzapRules    []DynamicBinzapRule
	dynamicBinzapMutex    sync.RWMutex // guards dynamicBinzapRules
	dynamicBinzapDiskMu   sync.Mutex   // serializes disk writes
	dynamicBinzapFilePath = appconfig.Path("configs/dynamic_rules/binzap_rules.json")
	dynamicBinzapLoadOnce sync.Once
)

// ensureLoaded lazily loads rules from disk exactly once per process. Unlike the
// previous implementation it performs NO filesystem writes and runs no work at
// package-import time, so importing binzap has no side effects.
func ensureLoaded() {
	dynamicBinzapLoadOnce.Do(func() { _ = LoadDynamicBinzapRules() })
}

// LoadDynamicBinzapRules loads rules from the JSON file if it exists. A missing
// file is treated as "no rules" and does NOT create anything on disk.
func LoadDynamicBinzapRules() error {
	data, err := os.ReadFile(dynamicBinzapFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			dynamicBinzapMutex.Lock()
			dynamicBinzapRules = []DynamicBinzapRule{}
			dynamicBinzapMutex.Unlock()
			return nil
		}
		return err
	}
	var rules []DynamicBinzapRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("parse %s: %w", dynamicBinzapFilePath, err)
	}
	dynamicBinzapMutex.Lock()
	dynamicBinzapRules = rules
	dynamicBinzapMutex.Unlock()
	return nil
}

// persistSnapshot writes the given snapshot atomically (temp file + rename) so a
// crash or concurrent writer can never leave a truncated JSON file. Disk writes
// are serialized by dynamicBinzapDiskMu.
func persistSnapshot(snap []DynamicBinzapRule) error {
	dynamicBinzapDiskMu.Lock()
	defer dynamicBinzapDiskMu.Unlock()

	dir := filepath.Dir(dynamicBinzapFilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".binzap_rules_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dynamicBinzapFilePath)
}

// snapshot returns a defensive copy of the current rule set.
func snapshot() []DynamicBinzapRule {
	dynamicBinzapMutex.RLock()
	defer dynamicBinzapMutex.RUnlock()
	out := make([]DynamicBinzapRule, len(dynamicBinzapRules))
	copy(out, dynamicBinzapRules)
	return out
}

// SaveDynamicBinzapRules atomically persists the current in-memory rule set.
func SaveDynamicBinzapRules() error { return persistSnapshot(snapshot()) }

// GetDynamicBinzapRules returns all active rules cast to the Rule interface.
func GetDynamicBinzapRules() []Rule {
	ensureLoaded()
	dynamicBinzapMutex.RLock()
	defer dynamicBinzapMutex.RUnlock()
	rules := make([]Rule, 0, len(dynamicBinzapRules))
	for i := range dynamicBinzapRules {
		copied := dynamicBinzapRules[i]
		rules = append(rules, &copied)
	}
	return rules
}

// GetRawDynamicBinzapRules returns concrete rules for serialization / REST API.
func GetRawDynamicBinzapRules() []DynamicBinzapRule {
	ensureLoaded()
	return snapshot()
}

// AddDynamicBinzapRule adds a new rule and persists the set atomically.
func AddDynamicBinzapRule(rule DynamicBinzapRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	ensureLoaded()
	dynamicBinzapMutex.Lock()
	for _, r := range dynamicBinzapRules {
		if r.IDStr == rule.IDStr {
			dynamicBinzapMutex.Unlock()
			return fmt.Errorf("rule with ID %s already exists", rule.IDStr)
		}
	}
	dynamicBinzapRules = append(dynamicBinzapRules, rule)
	snap := make([]DynamicBinzapRule, len(dynamicBinzapRules))
	copy(snap, dynamicBinzapRules)
	dynamicBinzapMutex.Unlock()
	return persistSnapshot(snap)
}

// UpdateDynamicBinzapRule updates an existing rule and persists atomically.
func UpdateDynamicBinzapRule(id string, rule DynamicBinzapRule) error {
	ensureLoaded()
	dynamicBinzapMutex.Lock()
	found := false
	for i, r := range dynamicBinzapRules {
		if r.IDStr == id {
			dynamicBinzapRules[i] = rule
			found = true
			break
		}
	}
	if !found {
		dynamicBinzapMutex.Unlock()
		return fmt.Errorf("rule with ID %s not found", id)
	}
	snap := make([]DynamicBinzapRule, len(dynamicBinzapRules))
	copy(snap, dynamicBinzapRules)
	dynamicBinzapMutex.Unlock()
	return persistSnapshot(snap)
}

// DeleteDynamicBinzapRule removes a rule by ID and persists atomically.
func DeleteDynamicBinzapRule(id string) error {
	ensureLoaded()
	dynamicBinzapMutex.Lock()
	index := -1
	for i, r := range dynamicBinzapRules {
		if r.IDStr == id {
			index = i
			break
		}
	}
	if index == -1 {
		dynamicBinzapMutex.Unlock()
		return fmt.Errorf("rule with ID %s not found", id)
	}
	dynamicBinzapRules = append(dynamicBinzapRules[:index], dynamicBinzapRules[index+1:]...)
	snap := make([]DynamicBinzapRule, len(dynamicBinzapRules))
	copy(snap, dynamicBinzapRules)
	dynamicBinzapMutex.Unlock()
	return persistSnapshot(snap)
}
