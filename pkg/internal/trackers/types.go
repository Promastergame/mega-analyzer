// Package trackers detects ad / analytics / fingerprinting SDKs
// (Exodus-style) bundled into an APK. Detection runs against:
//
//   - DEX class paths (smali / decompiled)
//   - Java import-style patterns
//   - Embedded URLs / hostnames inside the APK
//
// The signature corpus is derived from the Exodus Privacy database.
// See `exodus_db.json` for the full list. The DB is embedded into
// the binary so the analyzer stays self-contained.
package trackers

import "time"

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Category tags trackers by intent.
type Category string

const (
	CatAds         Category = "advertising"
	CatAnalytics   Category = "analytics"
	CatCrash       Category = "crash_reporting"
	CatLocation    Category = "location"
	CatFingerprint Category = "fingerprinting"
	CatPush        Category = "push_notifications"
	CatAttribution Category = "attribution"
	CatGeneric     Category = "generic"
)

// Tracker is a single signature record.
type Tracker struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Patterns []string `json:"patterns,omitempty"`
	Domains  []string `json:"domains,omitempty"`
	Website  string   `json:"website,omitempty"`
}

// Match represents one tracker detected inside the target.
type Match struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Website  string   `json:"website,omitempty"`
	Hits     []Hit    `json:"hits,omitempty"`
}

// Hit is a piece of evidence that triggered the match.
type Hit struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

// Report aggregates all detected trackers.
type Report struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Target      string           `json:"target"`
	Total       int              `json:"total"`
	ByCategory  map[Category]int `json:"by_category,omitempty"`
	Matches     []Match          `json:"matches,omitempty"`
	// Score 0..100 where higher = more privacy-invasive bundle.
	Score   int    `json:"score"`
	Verdict string `json:"verdict,omitempty"` // "clean" | "minimal" | "moderate" | "heavy" | "extreme"
}
