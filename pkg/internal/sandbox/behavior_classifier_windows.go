//go:build windows

package sandbox

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// windowsBehaviorClassifier implements BehaviorClassifier for Windows.
type windowsBehaviorClassifier struct {
	rules []ClassificationRule
}

func newBehaviorClassifier() BehaviorClassifier {
	return &windowsBehaviorClassifier{
		rules: DefaultRules(),
	}
}

// Analyze processes all events and returns behavior analysis.
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.4
func (bc *windowsBehaviorClassifier) Analyze(events []Event) *BehaviorAnalysis {
	analysis := &BehaviorAnalysis{
		RiskScore:      0,
		Techniques:     []MITRETechnique{},
		Indicators:     []BehaviorIndicator{},
		Classification: "Unknown",
		Confidence:     0.0,
	}

	if len(events) == 0 {
		return analysis
	}

	// Collectors finish independently. Sort a copy, then correlate within
	// the calling process: unrelated PIDs must never form an injection chain.
	ordered := make([]Event, 0, len(events))
	for _, event := range events {
		if event != nil && event.GetProcessID() > 0 {
			ordered = append(ordered, event)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].GetTimestamp().Before(ordered[j].GetTimestamp())
	})
	byPID := make(map[int][]Event)
	var pids []int
	for _, event := range ordered {
		pid := event.GetProcessID()
		if _, ok := byPID[pid]; !ok {
			pids = append(pids, pid)
		}
		byPID[pid] = append(byPID[pid], event)
	}

	// Apply each rule to the event sequence
	for _, rule := range bc.rules {
		var matches []Event
		for _, pid := range pids {
			matches = append(matches, bc.matchRule(rule, byPID[pid])...)
		}
		if len(matches) > 0 {
			// Rule matched, add technique
			technique := MITRETechnique{
				ID:          rule.Technique,
				Name:        rule.Name,
				Tactic:      rule.Tactic,
				Description: rule.Description,
				Evidence:    bc.formatEvidence(matches),
				Severity:    rule.Severity,
			}
			analysis.Techniques = append(analysis.Techniques, technique)

			// Add indicators for each match
			for _, event := range matches {
				indicator := BehaviorIndicator{
					Type:        rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Timestamp:   event.GetTimestamp(),
					ProcessID:   event.GetProcessID(),
					Details: map[string]interface{}{
						"technique": rule.Technique,
						"tactic":    rule.Tactic,
					},
				}
				analysis.Indicators = append(analysis.Indicators, indicator)
			}
		}
	}

	// Calculate risk score (weighted by severity)
	totalSeverity := 0
	for _, technique := range analysis.Techniques {
		totalSeverity += technique.Severity
	}

	// Normalize to 0-100 scale
	if totalSeverity > 0 {
		analysis.RiskScore = min(100, totalSeverity*10)
	}

	// Classify based on detected techniques
	analysis.Classification = bc.classifyBehavior(analysis.Techniques)

	// Calculate confidence based on number of techniques and evidence
	if len(analysis.Techniques) > 0 {
		analysis.Confidence = minFloat(1.0, float64(len(analysis.Techniques))/5.0)
	}

	return analysis
}

// AddRule adds a custom classification rule.
func (bc *windowsBehaviorClassifier) AddRule(rule ClassificationRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.Technique == "" {
		return fmt.Errorf("rule technique is required")
	}
	if rule.Severity < 1 || rule.Severity > 10 {
		return fmt.Errorf("rule severity must be between 1 and 10")
	}
	if len(rule.Pattern.Sequence) == 0 || rule.Pattern.MinMatches < 1 || rule.Pattern.TimeWindow < 0 {
		return fmt.Errorf("rule needs a non-empty sequence, positive minimum matches and non-negative time window")
	}

	bc.rules = append(bc.rules, rule)
	return nil
}

// GetRules returns all loaded classification rules.
func (bc *windowsBehaviorClassifier) GetRules() []ClassificationRule {
	return bc.rules
}

// matchRule checks if a rule matches the event sequence.
func (bc *windowsBehaviorClassifier) matchRule(rule ClassificationRule, events []Event) []Event {
	if len(rule.Pattern.Sequence) == 0 {
		return nil
	}

	// For single-event patterns
	if len(rule.Pattern.Sequence) == 1 {
		return bc.matchSingleEvent(rule, events)
	}

	// For multi-event sequence patterns
	return bc.matchSequence(rule, events)
}

// matchSingleEvent matches rules that look for multiple occurrences of a single event type.
func (bc *windowsBehaviorClassifier) matchSingleEvent(rule ClassificationRule, events []Event) []Event {
	matcher := rule.Pattern.Sequence[0]
	matches := []Event{}

	for _, event := range events {
		if bc.eventMatches(event, matcher) {
			if call, ok := event.(APICall); ok && !isSuccessfulCall(call) {
				continue
			}
			matches = append(matches, event)
		}
	}

	// Check if we have enough matches within the time window
	if len(matches) < rule.Pattern.MinMatches {
		return nil
	}

	// If time window is specified, check temporal constraint
	if rule.Pattern.TimeWindow > 0 {
		windowMatches := bc.filterByTimeWindow(matches, rule.Pattern.TimeWindow)
		if len(windowMatches) >= rule.Pattern.MinMatches {
			return windowMatches
		}
		return nil
	}

	return matches
}

// matchSequence matches rules that require a specific sequence of events.
func (bc *windowsBehaviorClassifier) matchSequence(rule ClassificationRule, events []Event) []Event {
	sequence := rule.Pattern.Sequence
	if rule.Pattern.MinMatches > len(sequence) {
		return nil
	}
	// Keep the latest partial match at each stage. A later start dominates
	// an earlier one for the time limit. Reverse traversal prevents an event
	// from satisfying more than one step, and avoids rescanning every suffix.
	states := make([][]Event, len(sequence))
	for _, event := range events {
		for step := len(sequence) - 1; step >= 0; step-- {
			if !bc.eventMatches(event, sequence[step]) {
				continue
			}
			if call, ok := event.(APICall); ok && !isSuccessfulCall(call) {
				continue
			}
			if step == 0 {
				states[0] = []Event{event}
				continue
			}
			previous := states[step-1]
			if len(previous) == 0 {
				continue
			}
			elapsed := event.GetTimestamp().Sub(previous[0].GetTimestamp())
			if elapsed < 0 || (rule.Pattern.TimeWindow > 0 && elapsed > rule.Pattern.TimeWindow) {
				continue
			}
			// Target correlation: same operation must act on the same process/
			// thread. Different explicit targets break the chain; calls without
			// target identity neither prove nor break it.
			if !targetsCorrelate(append(append([]Event(nil), previous...), event)) {
				continue
			}
			matches := append(append([]Event(nil), previous...), event)
			if step == len(sequence)-1 {
				if !allSuccessful(matches) {
					continue
				}
				return matches
			}
			states[step] = matches
		}
	}
	return nil
}

// normalizeAPIFunction strips A/W suffixes and maps NT native variants to
// their Win32 counterparts so rules written for one spelling also match the
// other. Comparison is case-insensitive.
// awSuffixedBases lists Win32 API base names that carry an ANSI (A) or
// Unicode (W) suffix. Only these may lose a trailing a/w during matching.
var awSuffixedBases = map[string]bool{
	"createprocess": true, "createfile": true, "createwindow": true,
	"createremotethread": true, "writeprocessmemory": true, "virtualallocex": true,
	"regcreatekeyex": true, "regsetvalueex": true, "regopenkeyex": true,
	"regqueryvalueex": true, "createevent": true, "createmutex": true,
	"createthread": true, "loadlibrary": true, "getprocaddress": true,
	"startservice": true, "registerservice": true, "outputdebugstring": true,
}

func normalizeAPIFunction(fn string) string {
	lower := strings.ToLower(strings.TrimSpace(fn))
	// Strip trailing A/W only for known ANSI/Unicode-suffixed Win32 APIs
	// (CreateProcessA -> createprocess). Blind stripping corrupts names that
	// genuinely end in 'a'/'w'.
	if len(lower) > 1 && (lower[len(lower)-1] == 'a' || lower[len(lower)-1] == 'w') {
		base := lower[:len(lower)-1]
		if awSuffixedBases[base] {
			lower = base
		}
	}
	aliases := map[string]string{
		"ntallocatevirtualmemory": "virtualallocex",
		"ntwritevirtualmemory":    "writeprocessmemory",
		"ntcreatethreadex":        "createremotethread",
		"createremotethreadex":    "createremotethread",
		"ntunmapviewofsection":    "ntunmapviewofsection",
		"ntresumethread":          "resumethread",
		"ntcreateuserprocess":     "createprocess",
		"zwcreateuserprocess":     "createprocess",
		"createprocessinternal":   "createprocess",
		"createprocessasuser":     "createprocess",
		"rtlcreateuserthread":     "createremotethread",
		"zwallocatevirtualmemory": "virtualallocex",
		"zwwritevirtualmemory":    "writeprocessmemory",
		"zwcreatethreadex":        "createremotethread",
		"zwunmapviewofsection":    "ntunmapviewofsection",
		"zwresumethread":          "resumethread",
		"bcryptencrypt":           "cryptencrypt",
		"ntsetvaluekey":           "regsetvalueex",
		"zwsetvaluekey":           "regsetvalueex",
	}
	if v, ok := aliases[lower]; ok {
		return v
	}
	return lower
}

func apiFunctionOf(eventType string) (string, bool) {
	if !strings.HasPrefix(eventType, "APICall:") {
		return "", false
	}
	return strings.TrimPrefix(eventType, "APICall:"), true
}

// targetKeysByNamespace extracts all explicit process/thread target identities
// carried by call.Parameters, keyed by namespace ("pid", "tid", "ph", "th").
// Unifying hProcess and ProcessHandle under "ph" (and hThread and ThreadHandle
// under "th") ensures mixed Win32/NT chains compare process handles in the same
// namespace while thread handles in ResumeThread do not collide with hProcess.
func targetKeysByNamespace(call APICall) map[string]string {
	var keys map[string]string
	setKey := func(ns, val string) {
		if keys == nil {
			keys = make(map[string]string, 2)
		}
		if _, exists := keys[ns]; !exists {
			keys[ns] = ns + ":" + strings.ToLower(val)
		}
	}

	for _, p := range call.Parameters {
		n := strings.ToLower(strings.TrimSpace(p.Name))
		v := strings.TrimSpace(p.Value)
		if v == "" || v == "0" || v == "0x0" || strings.EqualFold(v, "null") || strings.EqualFold(v, "pseudo") {
			continue
		}
		switch {
		case strings.Contains(n, "processid") || n == "pid" || n == "dwprocessid" || n == "targetpid":
			setKey("pid", v)
		case strings.Contains(n, "threadid") || n == "tid" || n == "dwthreadid" || n == "targettid":
			setKey("tid", v)
		case (strings.Contains(n, "process") && strings.Contains(n, "handle")) || n == "hprocess" || n == "handle":
			setKey("ph", v)
		case (strings.Contains(n, "thread") && strings.Contains(n, "handle")) || n == "hthread":
			setKey("th", v)
		}
	}
	return keys
}

// targetKey extracts the primary acted-upon process/thread identity from API
// params: hProcess/ProcessHandle/dwProcessId/pid/hThread and their NT equivalents.
// Empty means the call carries no target identity (can't disprove sameness).
func targetKey(call APICall) string {
	keys := targetKeysByNamespace(call)
	for _, ns := range []string{"pid", "tid", "ph", "th"} {
		if k, ok := keys[ns]; ok {
			return k
		}
	}
	return ""
}

// isSuccessfulCall reports whether the API call succeeded. NT/ZW/BCrypt calls
// use NTSTATUS (0 == success) and Reg* calls use LSTATUS (0 == ERROR_SUCCESS);
// Win32 handle/BOOL/pointer calls fail on 0/NULL/INVALID_HANDLE_VALUE/0xffffffff.
// Empty return values (legacy traces) are treated as unknown → allowed, so old
// data keeps working.
func isSuccessfulCall(call APICall) bool {
	v := strings.TrimSpace(call.ReturnValue)
	if v == "" {
		return true
	}
	lower := strings.ToLower(v)
	fnLower := strings.ToLower(strings.TrimSpace(call.Function))
	isZeroSuccess := strings.HasPrefix(fnLower, "nt") ||
		strings.HasPrefix(fnLower, "zw") ||
		strings.HasPrefix(fnLower, "rtl") ||
		strings.HasPrefix(fnLower, "bcrypt") ||
		strings.HasPrefix(fnLower, "reg") ||
		fnLower == "connect" ||
		fnLower == "wsaconnect" ||
		fnLower == "wsasend" ||
		fnLower == "wsarecv"

	isZeroVal := strings.Contains(lower, "status_success") ||
		strings.Contains(lower, "error_success") ||
		lower == "0" || lower == "0x0" || lower == "0x00000000"

	if isZeroSuccess {
		return isZeroVal
	}
	if isZeroVal {
		return false
	}
	if lower == "null" || lower == "false" || lower == "invalid_handle_value" || lower == "0xffffffff" || lower == "0xffffffffffffffff" {
		return false
	}
	// Non-zero NTSTATUS (e.g. 0xC0000022) is failure.
	if strings.HasPrefix(lower, "0xc") {
		return false
	}
	return true
}

// eventMatches checks if an event matches a matcher.
func (bc *windowsBehaviorClassifier) eventMatches(event Event, matcher EventMatcher) bool {
	// Check event type (API names normalized: A/W + NT aliases).
	if matcher.EventType != "" {
		et := event.GetEventType()
		if et != matcher.EventType && !strings.HasPrefix(et, matcher.EventType+":") {
			mFn, mOK := apiFunctionOf(matcher.EventType)
			eFn, eOK := apiFunctionOf(et)
			if !(mOK && eOK && normalizeAPIFunction(mFn) == normalizeAPIFunction(eFn)) {
				return false
			}
		}
	}

	// Check filters
	for key, value := range matcher.Filters {
		if !bc.filterMatches(event, key, value) {
			return false
		}
	}

	return true
}

// filterMatches checks if an event matches a specific filter.
func (bc *windowsBehaviorClassifier) filterMatches(event Event, key string, value interface{}) bool {
	switch key {
	case "path_contains":
		// For registry events, check if path contains any of the strings
		if ke, ok := event.(KernelEvent); ok {
			var patterns []string
			switch values := value.(type) {
			case []string:
				patterns = values
			case []interface{}: // JSON-decoded custom rules
				for _, item := range values {
					pattern, ok := item.(string)
					if !ok {
						return false
					}
					patterns = append(patterns, pattern)
				}
			default:
				return false
			}
			for _, pattern := range patterns {
				if pattern != "" && strings.Contains(strings.ToLower(ke.Path), strings.ToLower(pattern)) {
					return true
				}
			}
		}
		return false

	case "param_contains":
		// For API calls, check if any parameter contains the string
		if ac, ok := event.(APICall); ok {
			pattern, ok := value.(string)
			if !ok || pattern == "" {
				return false
			}
			for _, param := range ac.Parameters {
				if strings.Contains(param.Value, pattern) {
					return true
				}
			}
		}
		return false
	}

	return false // an unknown filter must not silently broaden a rule
}

// targetsCorrelate requires that all events with explicit target identity
// agree within each namespace (pid, tid, ph, th). Different explicit targets
// in any namespace break the chain.
func targetsCorrelate(chain []Event) bool {
	var seenByNS map[string]string
	for _, e := range chain {
		call, ok := e.(APICall)
		if !ok {
			continue
		}
		keys := targetKeysByNamespace(call)
		for ns, k := range keys {
			if seenByNS == nil {
				seenByNS = make(map[string]string, 2)
			}
			prev, exists := seenByNS[ns]
			if !exists {
				seenByNS[ns] = k
				continue
			}
			if prev != k {
				return false
			}
		}
	}
	return true
}

func allSuccessful(chain []Event) bool {
	for _, e := range chain {
		if call, ok := e.(APICall); ok && !isSuccessfulCall(call) {
			return false
		}
	}
	return true
}

// filterByTimeWindow filters events to those within a time window.
func (bc *windowsBehaviorClassifier) filterByTimeWindow(events []Event, window time.Duration) []Event {
	if len(events) == 0 {
		return events
	}

	// Analyze supplies sorted events from one PID. A sliding window is
	// linear even for large traces of repeated encryption/file operations.
	left, bestStart, bestEnd := 0, 0, 0
	for right := range events {
		for events[right].GetTimestamp().Sub(events[left].GetTimestamp()) > window {
			left++
		}
		if right+1-left > bestEnd-bestStart {
			bestStart, bestEnd = left, right+1
		}
	}
	return events[bestStart:bestEnd]
}

// formatEvidence formats matched events as evidence strings.
func (bc *windowsBehaviorClassifier) formatEvidence(events []Event) []string {
	evidence := []string{}
	for _, event := range events {
		evidence = append(evidence, fmt.Sprintf("%s at %s (PID %d)",
			event.GetEventType(),
			event.GetTimestamp().Format(time.RFC3339),
			event.GetProcessID()))
	}
	return evidence
}

// classifyBehavior assigns a classification based on detected techniques.
func (bc *windowsBehaviorClassifier) classifyBehavior(techniques []MITRETechnique) string {
	if len(techniques) == 0 {
		return "Unknown"
	}

	// Check for ransomware indicators
	for _, tech := range techniques {
		if tech.ID == "T1486" {
			return "Ransomware"
		}
	}

	// Check for trojan indicators (process injection, persistence)
	hasInjection := false
	hasPersistence := false
	for _, tech := range techniques {
		if strings.HasPrefix(tech.ID, "T1055") {
			hasInjection = true
		}
		if tech.ID == "T1547" {
			hasPersistence = true
		}
	}

	if hasInjection && hasPersistence {
		return "Trojan"
	}
	if hasInjection {
		return "Injector"
	}
	if hasPersistence {
		return "Persistence"
	}

	return "Suspicious"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
