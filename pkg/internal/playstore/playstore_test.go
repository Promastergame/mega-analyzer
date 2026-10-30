package playstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseBodyComprehensive(t *testing.T) {
	// 1. JSON-LD parsing + category
	body1 := `<script type="application/ld+json">{"name":"TestApp","description":"Welcome\u00a0to\u200bTestApp","author":{"name":"DevCorp"},"aggregateRating":{"ratingValue":"4.6","ratingCount":"2,500"},"applicationCategory":"Productivity"}</script>`
	m1 := parseBody("com.test", body1)
	if m1.Name != "TestApp" || m1.Developer != "DevCorp" || m1.Rating != 4.6 || m1.RatingCount != "2,500" || m1.Category != "Productivity" {
		t.Errorf("Unexpected metadata parsed from JSON-LD: %+v", m1)
	}
	if !m1.Found || m1.PackageName != "com.test" || m1.URL != "https://play.google.com/store/apps/details?id=com.test" {
		t.Errorf("Meta fields incorrect: %+v", m1)
	}

	// 2. JSON-LD invalid JSON branch
	bodyInvalid := `<script type="application/ld+json">invalid-json</script>`
	mInvalid := parseBody("com.test", bodyInvalid)
	if mInvalid.Name != "" {
		t.Error("Expected no fields to be parsed from invalid JSON-LD")
	}

	// 3. Fallback Regex Parsing (rating, version, updated, privacy)
	bodyRegex := `
		"ratingValue":"3.8"
		"ratingCount":"450"
		Current Version</div>
		<span class="any-class">1.2.3</span>
		Updated on</div>
		<span class="any-class">May 30, 2026</span>
		privacy_policy_url" href="https://example.com/privacy-policy"
	`
	mRegex := parseBody("com.test", bodyRegex)
	if mRegex.Rating != 3.8 || mRegex.RatingCount != "450" || mRegex.Version != "1.2.3" || mRegex.Updated != "May 30, 2026" || mRegex.PrivacyPolicy != "https://example.com/privacy-policy" {
		t.Errorf("Unexpected regex fallback parsing values: %+v", mRegex)
	}
}

func TestFetchMetadataEdgeCases(t *testing.T) {
	// 1. Empty package name
	meta, err := FetchMetadata("")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if meta == nil || meta.Error != "empty package name" {
		t.Errorf("Expected empty package name error inside metadata, got %+v", meta)
	}

	// 2. Invalid package names are rejected before any network I/O, with
	// the error inside metadata (same contract as the empty name).
	for _, bad := range []string{"com.test\napp", "com.test&foo=bar", "com.test?x=1", "..", "com..test", ".com", strings.Repeat("a", 300)} {
		meta, err := FetchMetadata(bad)
		if err != nil {
			t.Fatalf("FetchMetadata(%q): unexpected error: %v", bad, err)
		}
		if meta == nil || meta.Error != "invalid package name" {
			t.Errorf("FetchMetadata(%q): expected invalid-name metadata, got %+v", bad, meta)
		}
	}
}

func TestAnalyzeAndRenderMarkdown(t *testing.T) {
	// 1. Published App Report
	repPublished := &Report{
		GeneratedAt: "2026-05-30T00:00:00Z",
		Verdict:     "published",
		Metadata: &Metadata{
			PackageName:   "com.test.app",
			Name:          "TestApp",
			Developer:     "DevCorp",
			Category:      "Productivity",
			Rating:        4.5,
			RatingCount:   "1000",
			Installs:      "100k+",
			Version:       "1.0.0",
			Updated:       "May 2026",
			PrivacyPolicy: "https://example.com/privacy",
			URL:           "https://play.google.com/store/apps/details?id=com.test.app",
			Found:         true,
		},
	}

	mdPublished := repPublished.RenderMarkdown()
	if !strings.Contains(mdPublished, "# Play Store Metadata Report") || !strings.Contains(mdPublished, "**Package**: com.test.app") {
		t.Error("RenderMarkdown for published app failed")
	}

	// 2. Unregistered/Sideloaded App Report
	repSideloaded := &Report{
		GeneratedAt: "2026-05-30T00:00:00Z",
		Verdict:     "sideloaded",
		Metadata: &Metadata{
			Found: false,
		},
	}

	mdSideloaded := repSideloaded.RenderMarkdown()
	if !strings.Contains(mdSideloaded, "App not found on Google Play Store.") {
		t.Error("RenderMarkdown for sideloaded app failed")
	}

	// 3. Analyze helper (live network: skip under -short)
	if testing.Short() {
		t.Skip("live Play Store lookup skipped in short mode")
	}
	repA := Analyze("com.test.app")
	if repA == nil || repA.Verdict != "sideloaded" {
		// FetchMetadata on unknown package fails or returns not found
		t.Logf("Analyze returned: %+v", repA)
	}
}

func TestReviewMultilineJSONLDAndInstalls(t *testing.T) {
	body := "<script type=\"application/ld+json\">{\n" +
		"\"name\":\"MultiApp\",\n" +
		"\"author\":{\"name\":\"DevCo\"}\n" +
		"}</script>" +
		"<div>\"1,000,000+\"</div>"
	m := parseBody("com.multi.app", body)
	if m.Name != "MultiApp" || m.Developer != "DevCo" {
		t.Errorf("multiline JSON-LD missed: %+v", m)
	}
	if m.Installs != "1,000,000+" {
		t.Errorf("installs heuristic missed: %+v", m)
	}
	// Versions must not match the installs token.
	if m2 := parseBody("com.v", `<div>"1.2.3"</div>`); m2.Installs != "" {
		t.Errorf("version string matched installs: %+v", m2)
	}
}

func TestReviewRetryThenSuccess(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("id") != "com.retry.app" {
			t.Errorf("package id not passed through: %q", r.URL.RawQuery)
		}
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`<script type="application/ld+json">{"name":"RetryApp"}</script>`))
	}))
	defer srv.Close()

	meta, err := fetchMetadata(context.Background(), "com.retry.app", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.Found || meta.Name != "RetryApp" {
		t.Errorf("retry did not recover: %+v", meta)
	}
	if calls != 2 {
		t.Errorf("expected 2 attempts, got %d", calls)
	}
}

func TestReviewRetryExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	meta, err := fetchMetadata(context.Background(), "com.down.app", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Found || meta.Error != "HTTP 503" {
		t.Errorf("expected HTTP 503 metadata, got %+v", meta)
	}
}

func TestReviewContextCancel(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	meta, err := fetchMetadata(ctx, "com.cancel.app", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Error == "" {
		t.Errorf("cancelled context should surface an error, got %+v", meta)
	}
}
