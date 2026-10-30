// Package yara provides a lightweight YARA-like pattern matching engine
// for detecting telemetry SDKs, ad trackers, analytics libraries, and
// known malware signatures in binary and text files.
package yara

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RULE DEFINITION
// ═══════════════════════════════════════════════════════════════════════════════

// Rule is a single detection rule (equivalent to a YARA rule).
type Rule struct {
	Name        string
	Tags        []string
	Description string
	Author      string
	Severity    Severity
	Strings     []RuleString
	Condition   ConditionType
	Meta        map[string]string
}

// Severity levels for rule matches.
type Severity uint8

const (
	SevInfo   Severity = iota // informational (telemetry SDK detected)
	SevLow                    // low risk (common tracker)
	SevMedium                 // medium risk (aggressive data collector)
	SevHigh                   // high risk (known malicious)
	SevCrit                   // critical (confirmed malware signature)
)

func (s Severity) String() string {
	names := [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	if int(s) < len(names) {
		return names[s]
	}
	return "UNKNOWN"
}

// RuleString is a pattern within a rule.
type RuleString struct {
	ID       string
	Text     string         // for text patterns
	HexBytes []byte         // for hex patterns
	Regex    *regexp.Regexp // for regex patterns
	Kind     StringKind
	NoCase   bool
	Wide     bool // UTF-16LE match
}

// StringKind classifies the pattern type.
type StringKind uint8

const (
	StringText  StringKind = iota // literal string match
	StringHex                     // hex byte sequence
	StringRegex                   // regular expression
)

// ConditionType defines how strings must match.
type ConditionType uint8

const (
	CondAny ConditionType = iota // any string matches
	CondAll                      // all strings must match
	CondN                        // at least N strings match
)

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH RESULT
// ═══════════════════════════════════════════════════════════════════════════════

// Match represents a rule that matched a file.
type Match struct {
	Rule     *Rule
	File     string
	Hits     []Hit
	Severity Severity
}

// Hit is a single string match location.
type Hit struct {
	StringID string
	Offset   int64
	Length   int
	Data     []byte // matched bytes (capped to 64 bytes for display)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// Engine is the YARA-like scanner.
type Engine struct {
	Rules []*Rule
}

// NewEngine creates an engine with built-in telemetry/tracker rules.
func NewEngine() *Engine {
	e := &Engine{}
	e.loadBuiltinRules()
	return e
}

// AddRule adds a custom rule.
func (e *Engine) AddRule(r *Rule) {
	e.Rules = append(e.Rules, r)
}

// ScanFile scans a single file against all rules.
func (e *Engine) ScanFile(path string) ([]Match, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return e.ScanBytes(data, path), nil
}

// ScanBytes scans raw bytes against all rules.
func (e *Engine) ScanBytes(data []byte, filename string) []Match {
	var matches []Match
	dataLower := bytes.ToLower(data)
	for _, rule := range e.Rules {
		if m := e.matchRule(rule, data, dataLower, filename); m != nil {
			matches = append(matches, *m)
		}
	}
	return matches
}

func (e *Engine) matchRule(rule *Rule, data, dataLower []byte, filename string) *Match {
	var hits []Hit
	matched := 0

	for _, s := range rule.Strings {
		h := e.matchString(s, data, dataLower)
		if len(h) > 0 {
			hits = append(hits, h...)
			matched++
		}
	}

	ok := false
	switch rule.Condition {
	case CondAny:
		ok = matched > 0
	case CondAll:
		ok = matched == len(rule.Strings)
	case CondN:
		ok = matched >= 2 // default threshold
	}

	if !ok {
		return nil
	}
	return &Match{Rule: rule, File: filename, Hits: hits, Severity: rule.Severity}
}

func (e *Engine) matchString(s RuleString, data, dataLower []byte) []Hit {
	var hits []Hit
	switch s.Kind {
	case StringText:
		pattern := []byte(s.Text)
		searchData := data
		if s.NoCase {
			pattern = bytes.ToLower(pattern)
			searchData = dataLower
		}
		if s.Wide {
			pattern = toWide(pattern)
			// search in original data for wide strings
			searchData = data
		}
		offset := 0
		for {
			idx := bytes.Index(searchData[offset:], pattern)
			if idx < 0 {
				break
			}
			pos := offset + idx
			end := pos + len(pattern)
			if end > len(data) {
				end = len(data)
			}
			snippet := data[pos:end]
			if len(snippet) > 64 {
				snippet = snippet[:64]
			}
			hits = append(hits, Hit{StringID: s.ID, Offset: int64(pos), Length: len(pattern), Data: snippet})
			offset = pos + 1
			if offset >= len(searchData) {
				break
			}
		}
	case StringHex:
		offset := 0
		for {
			idx := bytes.Index(data[offset:], s.HexBytes)
			if idx < 0 {
				break
			}
			pos := offset + idx
			hits = append(hits, Hit{StringID: s.ID, Offset: int64(pos), Length: len(s.HexBytes), Data: s.HexBytes})
			offset = pos + 1
			if offset >= len(data) {
				break
			}
		}
	case StringRegex:
		if s.Regex != nil {
			locs := s.Regex.FindAllIndex(data, 100) // cap at 100 matches
			for _, loc := range locs {
				snippet := data[loc[0]:loc[1]]
				if len(snippet) > 64 {
					snippet = snippet[:64]
				}
				hits = append(hits, Hit{StringID: s.ID, Offset: int64(loc[0]), Length: loc[1] - loc[0], Data: snippet})
			}
		}
	}
	return hits
}

func toWide(b []byte) []byte {
	wide := make([]byte, len(b)*2)
	for i, c := range b {
		wide[i*2] = c
		wide[i*2+1] = 0
	}
	return wide
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILT-IN RULES — Telemetry / Trackers / Malware Indicators
// ═══════════════════════════════════════════════════════════════════════════════

func (e *Engine) loadBuiltinRules() {
	// --- Telemetry SDKs ---
	e.Rules = append(e.Rules,
		textRule("firebase_analytics", "Firebase Analytics", SevInfo,
			[]string{"telemetry", "google"},
			"com.google.firebase.analytics", "FirebaseAnalytics",
			"google_app_id", "firebase_database_url"),

		textRule("facebook_sdk", "Facebook SDK Tracker", SevLow,
			[]string{"telemetry", "facebook"},
			"com.facebook.appevents", "FacebookSdk.sdkInitialize",
			"com.facebook.GraphRequest", "fb_app_id"),

		textRule("appsflyer", "AppsFlyer Attribution", SevLow,
			[]string{"telemetry", "attribution"},
			"com.appsflyer.AppsFlyerLib", "AF_DEV_KEY",
			"sendDeepLinkData"),

		textRule("adjust_sdk", "Adjust SDK", SevLow,
			[]string{"telemetry", "attribution"},
			"com.adjust.sdk.Adjust", "AdjustConfig",
			"adjustEvent"),

		textRule("amplitude", "Amplitude Analytics", SevInfo,
			[]string{"telemetry", "analytics"},
			"com.amplitude.api.Amplitude", "AmplitudeClient",
			"logEvent"),

		textRule("mixpanel", "Mixpanel Analytics", SevInfo,
			[]string{"telemetry", "analytics"},
			"com.mixpanel.android.mpmetrics", "MixpanelAPI",
			"track"),

		// --- Aggressive Trackers ---
		textRule("comscore", "comScore Beacon", SevMedium,
			[]string{"tracker", "aggressive"},
			"com.comscore.Analytics", "comScore",
			"notifyHiddenEvent"),

		textRule("inmobi_ads", "InMobi Aggressive Ads", SevMedium,
			[]string{"tracker", "ads"},
			"com.inmobi.ads", "InMobiAdRequest",
			"setLocationWithCityStateCountry"),

		// --- Known Malware Patterns ---
		hexRule("dex_injector", "DEX Dynamic Loading (Suspicious)", SevHigh,
			[]string{"malware", "dynamic"},
			"6465782E0A303335", // "dex.\n035" — DEX magic in unexpected location
		),

		textRule("reflection_invoke", "Reflection-based Code Execution", SevMedium,
			[]string{"evasion", "reflection"},
			"java.lang.reflect.Method", "invoke(",
			"getDeclaredMethod", "setAccessible"),

		textRule("root_detection", "Root Detection Library", SevInfo,
			[]string{"protection", "root"},
			"com.scottyab.rootbeer", "RootBeer",
			"isRooted", "/system/xbin/su"),

		textRule("ssl_pinning", "SSL Certificate Pinning", SevInfo,
			[]string{"protection", "ssl"},
			"CertificatePinner", "sha256/",
			"X509TrustManager", "checkServerTrusted"),
	)
}

func textRule(name, desc string, sev Severity, tags []string, patterns ...string) *Rule {
	r := &Rule{
		Name:        name,
		Description: desc,
		Severity:    sev,
		Tags:        tags,
		Condition:   CondAny,
	}
	for i, p := range patterns {
		r.Strings = append(r.Strings, RuleString{
			ID:   fmt.Sprintf("$s%d", i),
			Text: p,
			Kind: StringText,
		})
	}
	return r
}

func hexRule(name, desc string, sev Severity, tags []string, hexPatterns ...string) *Rule {
	r := &Rule{
		Name:        name,
		Description: desc,
		Severity:    sev,
		Tags:        tags,
		Condition:   CondAny,
	}
	for i, h := range hexPatterns {
		b, _ := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		r.Strings = append(r.Strings, RuleString{
			ID:       fmt.Sprintf("$h%d", i),
			HexBytes: b,
			Kind:     StringHex,
		})
	}
	return r
}

// RenderReport outputs all matches as Markdown.
func RenderReport(matches []Match) string {
	if len(matches) == 0 {
		return "No YARA-like signatures matched.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Signature Scan Report\n\n")
	fmt.Fprintf(&b, "**%d rules matched**\n\n", len(matches))
	fmt.Fprintf(&b, "| Severity | Rule | Description | Hits | File |\n")
	fmt.Fprintf(&b, "|----------|------|-------------|------|------|\n")
	for _, m := range matches {
		fmt.Fprintf(&b, "| %s | `%s` | %s | %d | `%s` |\n",
			m.Severity, m.Rule.Name, m.Rule.Description, len(m.Hits), m.File)
	}
	return b.String()
}
