package sandbox

import (
	"fmt"
	"time"
)

// BehaviorClassifier automatically maps observed behaviors to MITRE ATT&CK
// techniques and assigns risk scores.
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.4
type BehaviorClassifier interface {
	// Analyze processes all events and returns behavior analysis
	Analyze(events []Event) *BehaviorAnalysis

	// AddRule adds a custom classification rule
	AddRule(rule ClassificationRule) error

	// GetRules returns all loaded classification rules
	GetRules() []ClassificationRule
}

// Event is a generic interface for all event types.
type Event interface {
	GetTimestamp() time.Time
	GetProcessID() int
	GetEventType() string
}

// ClassificationRule defines a pattern-based rule for behavior detection.
type ClassificationRule struct {
	Name        string
	Pattern     EventPattern
	Technique   string // MITRE ATT&CK ID (e.g., T1547, T1055)
	Tactic      string // MITRE ATT&CK Tactic (e.g., Persistence, Defense Evasion)
	Severity    int    // 1-10
	Description string
}

// EventPattern defines a pattern to match against event sequences.
type EventPattern struct {
	Sequence   []EventMatcher
	TimeWindow time.Duration
	MinMatches int
}

// EventMatcher defines criteria for matching a single event.
type EventMatcher struct {
	EventType string
	Filters   map[string]interface{}
}

// NewBehaviorClassifier creates a new behavior classifier with default rules.
func NewBehaviorClassifier() BehaviorClassifier {
	return newBehaviorClassifier()
}

// GetTimestamp implementations for event types

func (e KernelEvent) GetTimestamp() time.Time {
	return e.Timestamp
}

func (e KernelEvent) GetProcessID() int {
	return e.ProcessID
}

func (e KernelEvent) GetEventType() string {
	return e.EventType.String()
}

func (e APICall) GetTimestamp() time.Time {
	return e.Timestamp
}

func (e APICall) GetProcessID() int {
	return e.ProcessID
}

func (e APICall) GetEventType() string {
	return fmt.Sprintf("APICall:%s", e.Function)
}

func (e NetworkConnection) GetTimestamp() time.Time {
	return e.Timestamp
}

func (e NetworkConnection) GetProcessID() int {
	return e.ProcessID
}

func (e NetworkConnection) GetEventType() string {
	return fmt.Sprintf("NetworkConnection:%s", e.Protocol)
}

// Default classification rules

// RegistryPersistenceRule detects registry persistence via Run/RunOnce keys.
// Maps to MITRE T1547 (Boot or Logon Autostart Execution).
func RegistryPersistenceRule() ClassificationRule {
	return ClassificationRule{
		Name: "Registry Persistence",
		Pattern: EventPattern{
			Sequence: []EventMatcher{
				{
					EventType: "RegSetValue",
					Filters: map[string]interface{}{
						"path_contains": []string{
							"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
							"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
						},
					},
				},
			},
			TimeWindow: 0, // Single event
			MinMatches: 1,
		},
		Technique:   "T1547",
		Tactic:      "Persistence",
		Severity:    7,
		Description: "Registry persistence via Run/RunOnce keys",
	}
}

// ProcessInjectionRule detects process injection via memory APIs.
// Maps to MITRE T1055 (Process Injection).
func ProcessInjectionRule() ClassificationRule {
	return ClassificationRule{
		Name: "Process Injection",
		Pattern: EventPattern{
			Sequence: []EventMatcher{
				{
					EventType: "APICall:VirtualAllocEx",
				},
				{
					EventType: "APICall:WriteProcessMemory",
				},
				{
					EventType: "APICall:CreateRemoteThread",
				},
			},
			TimeWindow: 10 * time.Second,
			MinMatches: 3,
		},
		Technique:   "T1055",
		Tactic:      "Defense Evasion",
		Severity:    9,
		Description: "Process injection detected via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
	}
}

// ProcessHollowingRule detects process hollowing technique.
// Maps to MITRE T1055.012 (Process Hollowing).
func ProcessHollowingRule() ClassificationRule {
	return ClassificationRule{
		Name: "Process Hollowing",
		Pattern: EventPattern{
			Sequence: []EventMatcher{
				{
					EventType: "APICall:CreateProcessA",
					Filters: map[string]interface{}{
						"param_contains": "CREATE_SUSPENDED",
					},
				},
				{
					EventType: "APICall:NtUnmapViewOfSection",
				},
				{
					EventType: "APICall:WriteProcessMemory",
				},
				{
					EventType: "APICall:ResumeThread",
				},
			},
			TimeWindow: 10 * time.Second,
			MinMatches: 4,
		},
		Technique:   "T1055.012",
		Tactic:      "Defense Evasion",
		Severity:    10,
		Description: "Process hollowing detected",
	}
}

// RansomwareBehaviorRule detects mass file encryption patterns.
// Maps to MITRE T1486 (Data Encrypted for Impact).
func RansomwareBehaviorRule() ClassificationRule {
	return ClassificationRule{
		Name: "Ransomware Behavior",
		Pattern: EventPattern{
			Sequence: []EventMatcher{
				{
					EventType: "APICall:CryptEncrypt",
				},
			},
			TimeWindow: 60 * time.Second,
			MinMatches: 10, // Multiple encryption operations
		},
		Technique:   "T1486",
		Tactic:      "Impact",
		Severity:    10,
		Description: "Mass file encryption detected (potential ransomware)",
	}
}

// FileRenameFloodRule detects mass file renaming (ransomware indicator).
func FileRenameFloodRule() ClassificationRule {
	return ClassificationRule{
		Name: "Mass File Renaming",
		Pattern: EventPattern{
			Sequence: []EventMatcher{
				{
					EventType: "FileRename",
				},
			},
			TimeWindow: 60 * time.Second,
			MinMatches: 20, // Many rename operations
		},
		Technique:   "T1486",
		Tactic:      "Impact",
		Severity:    9,
		Description: "Mass file renaming detected (potential ransomware)",
	}
}

// DefaultRules returns the default set of classification rules.
func DefaultRules() []ClassificationRule {
	return []ClassificationRule{
		RegistryPersistenceRule(),
		ProcessInjectionRule(),
		ProcessHollowingRule(),
		RansomwareBehaviorRule(),
		FileRenameFloodRule(),
	}
}
