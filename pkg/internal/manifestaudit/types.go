// Package manifestaudit performs deep security audit of an Android
// manifest. Goes well beyond "list of permissions": classifies each
// exported component, flags missing permissions, deep-link
// vulnerabilities, debuggable / allowBackup / cleartext, taskAffinity
// hijacking, missing assetlinks.json, and more.
//
// Inspired by MobSF's manifest_analysis.py but written from scratch
// in Go around our local axml.Manifest model.
package manifestaudit

import "time"

// Severity uses the same lexicon as the rest of the project.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// ComponentKind identifies the manifest element family.
type ComponentKind string

const (
	KindActivity ComponentKind = "activity"
	KindService  ComponentKind = "service"
	KindReceiver ComponentKind = "receiver"
	KindProvider ComponentKind = "provider"
)

// Issue is a single audit finding.
type Issue struct {
	ID            string        `json:"id"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Severity      Severity      `json:"severity"`
	Score         int           `json:"score"`
	Component     string        `json:"component,omitempty"`
	ComponentKind ComponentKind `json:"component_kind,omitempty"`
	Reference     string        `json:"reference,omitempty"` // OWASP / CWE / MASVS
}

// ExportedComponent is an enriched view of a manifest component
// emitted in the report. Mirrors axml.Component but with derived
// "exported_effective" answer (Android default rules applied).
type ExportedComponent struct {
	Name              string        `json:"name"`
	Kind              ComponentKind `json:"kind"`
	ExportedDeclared  *bool         `json:"exported_declared,omitempty"`
	ExportedEffective bool          `json:"exported_effective"`
	HasIntentFilter   bool          `json:"has_intent_filter"`
	Permission        string        `json:"permission,omitempty"`
	ReadPermission    string        `json:"read_permission,omitempty"`
	WritePermission   string        `json:"write_permission,omitempty"`
	Authorities       string        `json:"authorities,omitempty"`
	IntentActions     []string      `json:"intent_actions,omitempty"`
	IntentCategories  []string      `json:"intent_categories,omitempty"`
	DeepLinks         []DeepLink    `json:"deep_links,omitempty"`
	// Risk explains the highest-severity reason this component is
	// flagged ("exported without permission", "world-readable
	// provider", "implicit deep link", "task hijack candidate", …).
	Risk     string   `json:"risk,omitempty"`
	Severity Severity `json:"severity,omitempty"`
}

// DeepLink describes a parsed VIEW intent-filter that maps a URL/scheme
// onto a component. Used to flag risky implicit deep links (no host /
// http(s) without assetlinks.json verification, etc).
type DeepLink struct {
	Scheme string `json:"scheme,omitempty"`
	// Host is the first declared host; kept for backward compatibility.
	Host string `json:"host,omitempty"`
	// Hosts is the complete ordered list of hosts declared by the
	// intent-filter's <data android:host> elements (deduplicated).
	Hosts []string `json:"hosts,omitempty"`
	// Verified reports android:autoVerify=true on the owning component's
	// intent filter (Android App Links; only https links can be verified).
	Verified bool `json:"verified,omitempty"`
}

// Report is the manifest audit output.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Target      string    `json:"target"`

	Package      string `json:"package,omitempty"`
	MinSDK       uint32 `json:"min_sdk,omitempty"`
	TargetSDK    uint32 `json:"target_sdk,omitempty"`
	VersionCode  uint32 `json:"version_code,omitempty"`
	VersionName  string `json:"version_name,omitempty"`
	SharedUserID string `json:"shared_user_id,omitempty"`

	// Application-level red flags.
	Debuggable        bool              `json:"debuggable"`
	AllowBackup       bool              `json:"allow_backup"`
	UsesCleartext     bool              `json:"uses_cleartext_traffic"`
	HasNetworkSecCfg  bool              `json:"has_network_security_config"`
	ExtractNativeLibs bool              `json:"extract_native_libs"`
	ApplicationPolicy ApplicationPolicy `json:"application_policy"`

	Issues              []Issue             `json:"issues"`
	ExportedComponents  []ExportedComponent `json:"exported_components,omitempty"`
	WorldAccessProvider []ExportedComponent `json:"world_access_providers,omitempty"`

	Counts struct {
		Activities int `json:"activities"`
		Services   int `json:"services"`
		Receivers  int `json:"receivers"`
		Providers  int `json:"providers"`

		ExportedActivities int `json:"exported_activities"`
		ExportedServices   int `json:"exported_services"`
		ExportedReceivers  int `json:"exported_receivers"`
		ExportedProviders  int `json:"exported_providers"`

		Critical int `json:"critical_issues"`
		High     int `json:"high_issues"`
		Medium   int `json:"medium_issues"`
		Low      int `json:"low_issues"`
		Info     int `json:"info_issues"`
	} `json:"counts"`

	// Score 0..100 — bigger = more attack surface / weaker hardening.
	Score   int    `json:"score"`
	Verdict string `json:"verdict,omitempty"` // "hardened" | "ok" | "weak" | "dangerous"
}
