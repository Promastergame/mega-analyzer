package yara

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SevInfo:       "INFO",
		SevLow:        "LOW",
		SevMedium:     "MEDIUM",
		SevHigh:       "HIGH",
		SevCrit:       "CRITICAL",
		Severity(123): "UNKNOWN",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestNewEngineLoadsBuiltins(t *testing.T) {
	e := NewEngine()
	if len(e.Rules) == 0 {
		t.Fatal("expected built-in rules to be loaded")
	}
	want := []string{
		"firebase_analytics",
		"facebook_sdk",
		"appsflyer",
		"reflection_invoke",
		"ssl_pinning",
		"dex_injector",
	}
	have := map[string]bool{}
	for _, r := range e.Rules {
		have[r.Name] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("missing built-in rule %q", n)
		}
	}
}

func TestAddRule(t *testing.T) {
	e := &Engine{}
	custom := &Rule{Name: "custom", Severity: SevHigh, Condition: CondAny,
		Strings: []RuleString{{ID: "$x", Text: "needle", Kind: StringText}}}
	e.AddRule(custom)
	if len(e.Rules) != 1 || e.Rules[0] != custom {
		t.Fatalf("AddRule did not store the rule")
	}
}

func TestScanBytesTextMatch(t *testing.T) {
	e := NewEngine()
	src := []byte(`some.code(); FirebaseAnalytics fa = ...; com.appsflyer.AppsFlyerLib af = ...`)
	matches := e.ScanBytes(src, "blob.smali")
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	names := map[string]bool{}
	for _, m := range matches {
		if m.File != "blob.smali" {
			t.Errorf("match file = %s, want blob.smali", m.File)
		}
		if len(m.Hits) == 0 {
			t.Errorf("match %s has no hits", m.Rule.Name)
		}
		for _, h := range m.Hits {
			if h.Length == 0 {
				t.Errorf("hit length is zero for %s", h.StringID)
			}
		}
		names[m.Rule.Name] = true
	}
	for _, want := range []string{"firebase_analytics", "appsflyer"} {
		if !names[want] {
			t.Errorf("expected %q to match", want)
		}
	}
}

func TestScanBytesEmpty(t *testing.T) {
	e := NewEngine()
	if got := e.ScanBytes([]byte("nothing here"), "x"); len(got) != 0 {
		t.Errorf("expected zero matches, got %d", len(got))
	}
}

func TestMatchStringNoCase(t *testing.T) {
	e := &Engine{}
	r := &Rule{Name: "case", Severity: SevLow, Condition: CondAny,
		Strings: []RuleString{{ID: "$s0", Text: "NEEDLE", Kind: StringText, NoCase: true}}}
	e.AddRule(r)
	matches := e.ScanBytes([]byte("found a needle in the haystack"), "f")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (case-insensitive), got %d", len(matches))
	}
}

func TestMatchStringWide(t *testing.T) {
	e := &Engine{}
	r := &Rule{Name: "wide", Severity: SevLow, Condition: CondAny,
		Strings: []RuleString{{ID: "$s0", Text: "AB", Kind: StringText, Wide: true}}}
	e.AddRule(r)
	// Construct a UTF-16LE buffer containing "AB".
	wideAB := []byte{'A', 0, 'B', 0}
	matches := e.ScanBytes(append([]byte("preamble"), wideAB...), "f")
	if len(matches) != 1 {
		t.Fatalf("expected wide-string match, got %d", len(matches))
	}
}

func TestMatchHex(t *testing.T) {
	e := &Engine{}
	r := &Rule{Name: "hex", Severity: SevHigh, Condition: CondAny,
		Strings: []RuleString{{ID: "$h0", HexBytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}, Kind: StringHex}}}
	e.AddRule(r)
	if got := e.ScanBytes([]byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x99}, "f"); len(got) != 1 {
		t.Fatalf("hex match failed, got %d", len(got))
	}
}

func TestMatchRegex(t *testing.T) {
	e := &Engine{}
	re := regexp.MustCompile(`token=[a-z0-9]{8}`)
	r := &Rule{Name: "regex", Severity: SevMedium, Condition: CondAny,
		Strings: []RuleString{{ID: "$r0", Regex: re, Kind: StringRegex}}}
	e.AddRule(r)
	matches := e.ScanBytes([]byte("auth?token=abcd1234&user=x"), "f")
	if len(matches) != 1 {
		t.Fatalf("regex match failed, got %d", len(matches))
	}
	if matches[0].Hits[0].Offset == 0 {
		t.Errorf("expected non-zero offset for regex hit")
	}
}

func TestMatchRegexNilSafe(t *testing.T) {
	e := &Engine{}
	r := &Rule{Name: "nilregex", Severity: SevLow, Condition: CondAny,
		Strings: []RuleString{{ID: "$r0", Kind: StringRegex /* Regex == nil */}}}
	e.AddRule(r)
	if got := e.ScanBytes([]byte("anything"), "f"); len(got) != 0 {
		t.Errorf("nil regex should not match, got %d", len(got))
	}
}

func TestConditionAll(t *testing.T) {
	e := &Engine{}
	r := &Rule{Name: "all", Severity: SevLow, Condition: CondAll,
		Strings: []RuleString{
			{ID: "$a", Text: "alpha", Kind: StringText},
			{ID: "$b", Text: "beta", Kind: StringText},
		}}
	e.AddRule(r)

	if got := e.ScanBytes([]byte("only alpha"), "f"); len(got) != 0 {
		t.Errorf("CondAll should reject partial match")
	}
	if got := e.ScanBytes([]byte("alpha and beta"), "f"); len(got) != 1 {
		t.Errorf("CondAll should accept full match")
	}
}

func TestConditionN(t *testing.T) {
	e := &Engine{}
	r := &Rule{Name: "n", Severity: SevLow, Condition: CondN,
		Strings: []RuleString{
			{ID: "$a", Text: "x1", Kind: StringText},
			{ID: "$b", Text: "x2", Kind: StringText},
			{ID: "$c", Text: "x3", Kind: StringText},
		}}
	e.AddRule(r)
	if got := e.ScanBytes([]byte("x1 only"), "f"); len(got) != 0 {
		t.Errorf("CondN should require ≥2 matches")
	}
	if got := e.ScanBytes([]byte("x1 and x2"), "f"); len(got) != 1 {
		t.Errorf("CondN should accept ≥2 matches")
	}
}

func TestScanFileReadsAndScans(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "demo.smali")
	if err := os.WriteFile(p, []byte("FirebaseAnalytics is here"), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, err := NewEngine().ScanFile(p)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(matches) == 0 {
		t.Errorf("expected matches when scanning the seeded file")
	}
}

func TestScanFileMissing(t *testing.T) {
	if _, err := NewEngine().ScanFile(filepath.Join(t.TempDir(), "no.such.file")); err == nil {
		t.Error("ScanFile must surface missing-file error")
	}
}

func TestRenderReportEmpty(t *testing.T) {
	if got := RenderReport(nil); !strings.Contains(got, "No YARA-like signatures") {
		t.Errorf("empty report missing baseline message: %q", got)
	}
}

func TestRenderReportPopulated(t *testing.T) {
	rule := &Rule{Name: "demo", Description: "demo rule", Severity: SevHigh}
	report := RenderReport([]Match{{Rule: rule, File: "x.smali", Severity: SevHigh,
		Hits: []Hit{{StringID: "$a", Offset: 12, Length: 5}}}})
	for _, want := range []string{"Signature Scan Report", "demo", "x.smali", "HIGH"} {
		if !strings.Contains(report, want) {
			t.Errorf("rendered report missing %q\n%s", want, report)
		}
	}
}

func TestToWide(t *testing.T) {
	in := []byte("AB")
	got := toWide(in)
	want := []byte{'A', 0, 'B', 0}
	if string(got) != string(want) {
		t.Errorf("toWide(%q) = %v, want %v", in, got, want)
	}
}
