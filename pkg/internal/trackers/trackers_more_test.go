package trackers

import (
	"strings"
	"testing"
)

func TestRenderMarkdown_Nil(t *testing.T) {
	md := RenderMarkdown(nil)
	if !strings.Contains(md, "no report") {
		t.Errorf("nil report should say 'no report', got:\n%s", md)
	}
}

func TestRenderMarkdown_Clean(t *testing.T) {
	r := &Report{
		Target:     "app.apk",
		Total:      0,
		ByCategory: map[Category]int{},
		Verdict:    "clean",
	}
	md := RenderMarkdown(r)
	if !strings.Contains(md, "Tracker Detection") {
		t.Errorf("expected header, got:\n%s", md)
	}
	if !strings.Contains(md, "app.apk") {
		t.Errorf("expected target name, got:\n%s", md)
	}
}

func TestRenderMarkdown_WithMatches(t *testing.T) {
	r := &Report{
		Target:     "app.apk",
		Total:      2,
		ByCategory: map[Category]int{CatAnalytics: 1, CatAds: 1},
		Verdict:    "moderate",
		Score:      30,
		Matches: []Match{
			{ID: "fb", Name: "Facebook Ads", Category: CatAds, Severity: SevHigh,
				Hits: []Hit{{File: "code.smali", Pattern: "com/facebook/ads"}}},
			{ID: "ga", Name: "Google Analytics", Category: CatAnalytics, Severity: SevMedium,
				Hits: []Hit{{File: "Main.java", Pattern: "GoogleAnalytics"}}},
		},
	}
	md := RenderMarkdown(r)
	if !strings.Contains(md, "Facebook Ads") {
		t.Errorf("expected tracker name in output")
	}
	if !strings.Contains(md, "analytics") {
		t.Errorf("expected category in output")
	}
}

func TestLoadDB(t *testing.T) {
	db, err := LoadDB()
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}
	if len(db) == 0 {
		t.Error("expected non-empty tracker DB")
	}
}
