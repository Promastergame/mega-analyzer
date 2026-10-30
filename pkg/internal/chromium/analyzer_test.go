package chromium

import (
	"strings"
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SevInfo, "INFO"},
		{SevLow, "LOW"},
		{SevMedium, "MEDIUM"},
		{SevHigh, "HIGH"},
		{SevCrit, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}
	for _, c := range cases {
		if got := c.sev.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestNewAnalyzerLoadsPatterns(t *testing.T) {
	a := NewAnalyzer()
	if len(a.Patterns) == 0 {
		t.Fatal("expected built-in patterns to be loaded")
	}
	// Sanity-check that the well-known WebView, JS bridge, and fingerprint
	// patterns survive the loader.
	wantIDs := []string{
		"CHROMIUM-WV-001", "CHROMIUM-WV-004",
		"CHROMIUM-JS-001",
		"CHROMIUM-DATA-001",
		"CHROMIUM-FP-001",
	}
	have := map[string]bool{}
	for _, p := range a.Patterns {
		have[p.ID] = true
	}
	for _, id := range wantIDs {
		if !have[id] {
			t.Errorf("missing built-in pattern %q", id)
		}
	}
}

func TestAnalyzeFileMatchesIndicators(t *testing.T) {
	a := NewAnalyzer()

	src := []byte(strings.Join([]string{
		"// dummy WebView setup",
		"settings.setJavaScriptEnabled(true);",
		"settings.setAllowFileAccess(true);",
		"webView.addJavascriptInterface(new Bridge(), \"android\");",
		"WebView.setWebContentsDebuggingEnabled(true);",
		"String c = CookieManager.getInstance().getCookie(url);",
		"canvas.getContext(\"2d\").getImageData(0,0,1,1);",
	}, "\n"))

	findings := a.AnalyzeFile("WebActivity.java", src)
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Each finding must reference a non-nil pattern and have a >0 line.
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Pattern == nil {
			t.Fatalf("finding has nil pattern: %+v", f)
		}
		if f.Line <= 0 {
			t.Errorf("non-positive line for %s", f.Pattern.ID)
		}
		seen[f.Pattern.ID] = true
	}

	wantTouched := []string{
		"CHROMIUM-WV-001", "CHROMIUM-WV-002", "CHROMIUM-WV-004",
		"CHROMIUM-JS-001",
		"CHROMIUM-DATA-001",
		"CHROMIUM-FP-001",
	}
	for _, id := range wantTouched {
		if !seen[id] {
			t.Errorf("expected pattern %q to fire on the seeded source", id)
		}
	}
}

func TestAnalyzeFileFiltersByExtension(t *testing.T) {
	a := &Analyzer{}
	a.Patterns = []*Pattern{{
		ID:         "TEST-JSON-ONLY",
		Name:       "JSON-only rule",
		Category:   CatExtensionAbuse,
		Severity:   SevLow,
		Indicators: []string{"matches"},
		FileFilter: "*.json",
	}}

	hits := a.AnalyzeFile("manifest.smali", []byte("matches"))
	if len(hits) != 0 {
		t.Errorf("smali file should not match a *.json filter, got %d hits", len(hits))
	}

	hits = a.AnalyzeFile("manifest.json", []byte("matches"))
	if len(hits) != 1 {
		t.Errorf("json file should match the *.json filter, got %d hits", len(hits))
	}
}

func TestAnalyzeFileNoFalsePositives(t *testing.T) {
	a := NewAnalyzer()
	clean := []byte("public class Plain { void noop() {} }")
	if hits := a.AnalyzeFile("Plain.java", clean); len(hits) != 0 {
		t.Errorf("expected zero findings for clean source, got %d", len(hits))
	}
}

func TestRenderReportEmpty(t *testing.T) {
	a := NewAnalyzer()
	rep := a.RenderReport()
	if !strings.Contains(rep, "No Chromium-specific vulnerabilities") {
		t.Errorf("empty report missing baseline message: %q", rep)
	}
}

func TestRenderReportWithFindings(t *testing.T) {
	a := NewAnalyzer()
	src := []byte("settings.setJavaScriptEnabled(true);\n" +
		"webView.addJavascriptInterface(bridge, \"x\");\n")
	a.AnalyzeFile("X.java", src)

	rep := a.RenderReport()
	if !strings.Contains(rep, "Chromium-Aware Analysis Report") {
		t.Errorf("report header missing: %q", rep)
	}
	if !strings.Contains(rep, "findings detected") {
		t.Errorf("report missing summary count")
	}
	// At least one severity label should be present (HIGH/CRITICAL/MEDIUM).
	if !strings.ContainsAny(rep, "HIGHCRITICALMEDIUM") {
		t.Errorf("report missing severity column data")
	}
}

func TestAnalyzeFileAccumulatesFindings(t *testing.T) {
	a := NewAnalyzer()
	src := []byte("settings.setJavaScriptEnabled(true);\n")
	_ = a.AnalyzeFile("A.java", src)
	_ = a.AnalyzeFile("B.java", src)
	if len(a.Findings) < 2 {
		t.Errorf("expected accumulated findings ≥ 2, got %d", len(a.Findings))
	}
}

func TestAnalyzeFileSkipsCommentLines(t *testing.T) {
	a := NewAnalyzer()
	src := []byte(strings.Join([]string{
		"// settings.setJavaScriptEnabled(true);",
		"# webView.addJavascriptInterface(bridge, \"x\");",
		"<!-- <uses-cleartextTraffic -->",
		"* setAllowFileAccess(true)",
		"settings.setJavaScriptEnabled(true); // trailing comment still counts",
	}, "\n"))
	findings := a.AnalyzeFile("X.java", src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (code line only), got %d: %+v", len(findings), findings)
	}
	if findings[0].Pattern.ID != "CHROMIUM-WV-001" {
		t.Errorf("wrong pattern fired: %s", findings[0].Pattern.ID)
	}
}

func TestNewHighValuePatternsFire(t *testing.T) {
	a := NewAnalyzer()
	src := []byte(strings.Join([]string{
		"public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.proceed(); }",
		"<application android:usesCleartextTraffic=\"true\">",
		"web.getSettings().setSafeBrowsingEnabled(false);",
		"public void onPermissionRequest(PermissionRequest r) { r.grant(r.getResources()); }",
	}, "\n"))
	hits := a.AnalyzeFile("Vuln.java", src)
	seen := map[string]Severity{}
	for _, f := range hits {
		seen[f.Pattern.ID] = f.Pattern.Severity
	}
	want := map[string]Severity{
		"CHROMIUM-WV-005":  SevHigh,
		"CHROMIUM-NET-001": SevHigh,
		"CHROMIUM-WV-006":  SevLow,
		"CHROMIUM-WV-007":  SevMedium,
	}
	for id, sev := range want {
		got, ok := seen[id]
		if !ok {
			t.Errorf("expected pattern %q to fire", id)
			continue
		}
		if got != sev {
			t.Errorf("pattern %q severity = %v, want %v", id, got, sev)
		}
	}
}

func TestNarrowedIndicatorsNoFalsePositives(t *testing.T) {
	a := NewAnalyzer()
	// Each line tripped the OLD broad indicators but is benign.
	clean := []byte(strings.Join([]string{
		"String v = myApi.getCookie(session);",
		"for (String l : logins) { print(l); }",
		"import android.view.autofill.AutofillManager;",
	}, "\n"))
	for _, f := range a.AnalyzeFile("Clean.java", clean) {
		switch f.Pattern.ID {
		case "CHROMIUM-DATA-001", "CHROMIUM-CRED-001", "CHROMIUM-CRED-002":
			t.Errorf("false positive: %s fired on %q", f.Pattern.ID, f.Snippet)
		}
	}
	theme := []byte(`{"background": "#ffffff", "theme_color": "#000000"}`)
	for _, f := range a.AnalyzeFile("theme.json", theme) {
		if f.Pattern.ID == "CHROMIUM-EXT-002" {
			t.Errorf("false positive: EXT-002 fired on theme JSON")
		}
	}
	// ...while the real store accesses still fire.
	evil := []byte("Cursor c = db.rawQuery(\"SELECT password_value FROM logins\", null);")
	fired := false
	for _, f := range a.AnalyzeFile("Evil.java", evil) {
		if f.Pattern.ID == "CHROMIUM-CRED-001" {
			fired = true
		}
	}
	if !fired {
		t.Errorf("expected CRED-001 to fire on Login Data column access")
	}
}

func TestFileFilterExactName(t *testing.T) {
	a := &Analyzer{}
	a.Patterns = []*Pattern{{
		ID:         "TEST-EXACT",
		Name:       "exact-name rule",
		Category:   CatWebViewMisconfig,
		Severity:   SevLow,
		Indicators: []string{"needle"},
		FileFilter: "AndroidManifest.xml",
	}}
	if hits := a.AnalyzeFile("Other.xml", []byte("needle")); len(hits) != 0 {
		t.Errorf("exact filter should not match Other.xml, got %d hits", len(hits))
	}
	if hits := a.AnalyzeFile("AndroidManifest.xml", []byte("needle")); len(hits) != 1 {
		t.Errorf("exact filter should match AndroidManifest.xml, got %d hits", len(hits))
	}
}

func TestRenderReportDeterministic(t *testing.T) {
	build := func() string {
		a := NewAnalyzer()
		a.AnalyzeFile("A.java", []byte("settings.setJavaScriptEnabled(true);\n"))
		a.AnalyzeFile("B.java", []byte("webView.addJavascriptInterface(b, \"x\");\n"))
		a.AnalyzeFile("C.xml", []byte("<application android:usesCleartextTraffic=\"true\">\n"))
		return a.RenderReport()
	}
	first, second := build(), build()
	if first != second {
		t.Fatalf("report not deterministic:\n%s\n---\n%s", first, second)
	}
	// Categories must appear in sorted order.
	order := []string{"cleartext-traffic", "javascript-bridge", "webview-misconfiguration"}
	last := -1
	for _, cat := range order {
		idx := strings.Index(first, "## "+cat)
		if idx < 0 {
			t.Fatalf("report missing category %q", cat)
		}
		if idx < last {
			t.Fatalf("categories out of order in report")
		}
		last = idx
	}
}
