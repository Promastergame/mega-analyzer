package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func hasTech(dets []TechDetection, name string) *TechDetection {
	for i := range dets {
		if dets[i].Name == name {
			return &dets[i]
		}
	}
	return nil
}

func TestFingerprint_HeadersWithVersion(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.24.0")
	h.Set("X-Powered-By", "PHP/8.2.11")
	dets := fingerprintSite(h, nil, "")
	if d := hasTech(dets, "nginx"); d == nil || d.Version != "1.24.0" {
		t.Errorf("nginx 1.24.0 not detected, got %+v", dets)
	}
	if d := hasTech(dets, "PHP"); d == nil || d.Version != "8.2.11" {
		t.Errorf("PHP 8.2.11 not detected, got %+v", dets)
	}
}

func TestFingerprint_Cookies(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "BITRIX_SM_UID"},
		{Name: "laravel_session"},
		{Name: "_ym_uid"},
	}
	dets := fingerprintSite(http.Header{}, cookies, "")
	for _, want := range []string{"1C-Bitrix", "Laravel", "Yandex Metrika"} {
		if hasTech(dets, want) == nil {
			t.Errorf("%s not detected from cookies, got %v", want, namesOf(dets))
		}
	}
}

func TestFingerprint_MetaGenerator(t *testing.T) {
	body := `<head><meta name="generator" content="WordPress 6.4.3"><title>Blog</title></head>`
	dets := fingerprintSite(http.Header{}, nil, body)
	d := hasTech(dets, "WordPress")
	if d == nil {
		t.Fatalf("WordPress not detected from meta generator, got %v", namesOf(dets))
	}
	if d.Version != "6.4.3" {
		t.Errorf("WordPress version = %q, want 6.4.3", d.Version)
	}
	if !strings.Contains(d.Evidence, "generator") {
		t.Errorf("evidence should mention generator, got %q", d.Evidence)
	}
}

func TestFingerprint_BodyPatternsAndVersion(t *testing.T) {
	body := `<script src="/_next/static/chunks/main.js"></script>` +
		`<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>` +
		`<script src="https://mc.yandex.ru/metrika/tag.js"></script>` +
		`<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">`
	dets := fingerprintSite(http.Header{}, nil, body)
	for _, want := range []string{"Next.js", "WordPress", "Yandex Metrika", "Bootstrap"} {
		if hasTech(dets, want) == nil {
			t.Errorf("%s not detected, got %v", want, namesOf(dets))
		}
	}
	if d := hasTech(dets, "jQuery"); d == nil || d.Version != "3.7.1" {
		t.Errorf("jQuery 3.7.1 not detected, got %+v", hasTech(dets, "jQuery"))
	}
	if d := hasTech(dets, "Bootstrap"); d == nil || d.Version != "5.3.3" {
		t.Errorf("Bootstrap 5.3.3 not detected, got %+v", hasTech(dets, "Bootstrap"))
	}
}

func TestFingerprint_RuBuilders(t *testing.T) {
	body := `<script src="https://static.tilda.cc/script.js"></script><div class="t-rec"></div>`
	dets := fingerprintSite(http.Header{}, nil, body)
	if hasTech(dets, "Tilda") == nil {
		t.Errorf("Tilda not detected, got %v", namesOf(dets))
	}
}

func TestFingerprint_NoFalsePositivesOnEmptyPage(t *testing.T) {
	dets := fingerprintSite(http.Header{}, nil, "<html><body>Hello</body></html>")
	if len(dets) != 0 {
		t.Errorf("expected 0 detections on empty page, got %v", namesOf(dets))
	}
}

func TestFingerprint_ConfidenceFlagged(t *testing.T) {
	dets := fingerprintSite(http.Header{}, nil, `<html><meta name="twitter:card"></html>`)
	d := hasTech(dets, "Twitter Cards")
	if d == nil {
		t.Fatalf("Twitter Cards not detected, got %v", namesOf(dets))
	}
	if d.Confidence != confProbable {
		t.Errorf("Twitter Cards confidence = %q, want probable", d.Confidence)
	}
}

func TestExtractPageTitle(t *testing.T) {
	if got := extractPageTitle("<html><head><title>  My \n Site </title></head>"); got != "My Site" {
		t.Errorf("extractPageTitle = %q", got)
	}
	if got := extractPageTitle("<title>Frühling</title>"); got != "Frühling" {
		t.Errorf("unicode title = %q", got)
	}
	if got := extractPageTitle("no title here"); got != "" {
		t.Errorf("expected empty title, got %q", got)
	}
}

func TestTechSummary_PicksKeyStack(t *testing.T) {
	dets := []TechDetection{
		{Name: "jQuery", Category: "JS library", Confidence: confCertain},
		{Name: "WordPress", Category: "CMS", Version: "6.4", Confidence: confCertain},
		{Name: "PHP", Category: "Language", Version: "8.1", Confidence: confCertain},
		{Name: "nginx", Category: "Web server", Version: "1.24", Confidence: confCertain},
		{Name: "Twitter Cards", Category: "Meta protocol", Confidence: confProbable},
	}
	got := techSummary(dets)
	want := "WordPress 6.4 · PHP 8.1 · nginx 1.24"
	if got != want {
		t.Errorf("techSummary = %q, want %q", got, want)
	}
}

// E2E: full HTTP path through handleTechDetect against a realistic page.
func TestHandleTechDetect_E2E_RichSite(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.1.27")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		http.SetCookie(w, &http.Cookie{Name: "BITRIX_SM_UID", Value: "1"})
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Тестовый сайт</title>` +
			`<script src="/bitrix/js/main/core/core.js"></script>` +
			`<script src="https://mc.yandex.ru/metrika/tag.js"></script>` +
			`<script src="/bitrix/js/jquery/jquery.min.js?ver=3.6.4"></script></head>` +
			`<body><div class="bx-core">hi</div></body></html>`))
	}))
	defer ts.Close()

	s := pentestServer()
	w := postJSON(s, s.handleTechDetect, `{"url":"`+ts.URL+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Title    string `json:"title"`
		Summary  string `json:"summary"`
		Detected []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"detected"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.Title != "Тестовый сайт" {
		t.Errorf("title = %q", resp.Title)
	}
	found := map[string]string{}
	for _, d := range resp.Detected {
		found[d.Name] = d.Version
	}
	for _, want := range []string{"nginx", "PHP", "1C-Bitrix", "Yandex Metrika", "jQuery"} {
		if _, ok := found[want]; !ok {
			t.Errorf("%s missing from response; got %v", want, found)
		}
	}
	if found["nginx"] != "1.24.0" || found["PHP"] != "8.1.27" {
		t.Errorf("versions wrong: nginx=%q php=%q", found["nginx"], found["PHP"])
	}
	if !strings.Contains(resp.Summary, "1C-Bitrix") {
		t.Errorf("summary = %q, want 1C-Bitrix mentioned", resp.Summary)
	}
}

// Regression: bare "ym1" in minified JS must not trigger Yandex Metrika
// (found live on mrbeast.art via the old weak `ym(\d+)` pattern).
func TestFingerprint_MetrikaNoFalsePositiveOnYmSubstring(t *testing.T) {
	dets := fingerprintSite(http.Header{}, nil, `<div class="xym123" data-ym1="foo"></div>`)
	if hasTech(dets, "Yandex Metrika") != nil {
		t.Errorf("Yandex Metrika false positive on 'ym1', got %v", namesOf(dets))
	}
	// while the real counter call must match
	dets = fingerprintSite(http.Header{}, nil, `<script>ym(12345678,"init",{});</script>`)
	if hasTech(dets, "Yandex Metrika") == nil {
		t.Errorf("real ym(N, init) call not detected")
	}
}

func TestFingerprint_ViteAndReact19(t *testing.T) {
	// Fragment of a real Vite-built page (mrbeast.art).
	body := `<script type="module">if(a&&a.supports&&a.supports("modulepreload"))return;` +
		`var n=Symbol.for("react.transitional.element");</script>`
	dets := fingerprintSite(http.Header{}, nil, body)
	if hasTech(dets, "Vite") == nil {
		t.Errorf("Vite not detected, got %v", namesOf(dets))
	}
	if hasTech(dets, "React") == nil {
		t.Errorf("React 19 marker not detected, got %v", namesOf(dets))
	}
}

func TestFingerprint_RegRuParking(t *testing.T) {
	// Fragment of a real REG.RU parking page (mega-analyzer.lol).
	body := `<html class="is_adaptive" lang="ru"><body class="b-page b-page_type_parking b-parking">` +
		`<meta name="parking" content="regru-rdap">` +
		`<script src="https://yandex.ru/ads/system/context.js" async></script>` +
		`<script>window.yaContextCb=window.yaContextCb||[]</script></body></html>`
	dets := fingerprintSite(http.Header{}, nil, body)
	if hasTech(dets, "REG.RU Parking") == nil {
		t.Errorf("REG.RU Parking not detected, got %v", namesOf(dets))
	}
	if hasTech(dets, "Yandex Direct") == nil {
		t.Errorf("Yandex RTB ads not detected, got %v", namesOf(dets))
	}
}

// E2E: redirect chain is followed (each hop SSRF-revalidated) up to the final page.
func TestHandleTechDetect_E2E_FollowsRedirects(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.26.0")
		w.Write([]byte(`<html><head><title>Final</title><meta name="generator" content="WordPress 6.5"></head></html>`))
	}))
	defer final.Close()

	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/landing", http.StatusFound)
	}))
	defer hop.Close()

	s := pentestServer()
	w := postJSON(s, s.handleTechDetect, `{"url":"`+hop.URL+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		FinalURL  string                           `json:"final_url"`
		Redirects []redirectHop                    `json:"redirects"`
		Detected  []struct{ Name, Version string } `json:"detected"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp.FinalURL != final.URL+"/landing" {
		t.Errorf("final_url = %q, want %s/landing", resp.FinalURL, final.URL)
	}
	if len(resp.Redirects) != 1 || resp.Redirects[0].Status != 302 {
		t.Errorf("redirect chain = %+v", resp.Redirects)
	}
	found := map[string]string{}
	for _, d := range resp.Detected {
		found[d.Name] = d.Version
	}
	if found["nginx"] != "1.26.0" || found["WordPress"] != "6.5" {
		t.Errorf("final page not fingerprinted: %v", found)
	}
}

// A redirect that pivots onto a private/internal address must be refused
// mid-chain: every hop of fetchFinalPage goes through safeHTTPClient again.
func TestFetchFinalPage_PrivateRedirectBlockedMidChain(t *testing.T) {
	// SSRF bypass lets hop 1 (localhost httptest server) through; the handler
	// stalls until the test flips the bypass off, so hop 2 is validated strictly.
	proceed := make(chan struct{})
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-proceed
		http.Redirect(w, r, "http://127.0.0.1:9/admin", http.StatusFound)
	}))
	defer hop.Close()

	isTestingBypassSSRF.Store(true)
	defer isTestingBypassSSRF.Store(false)

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		_, _, _, err := fetchFinalPage(hop.URL)
		done <- result{err}
	}()

	// Wait until hop 1 is being served, then re-enable strict SSRF checks.
	time.Sleep(50 * time.Millisecond)
	isTestingBypassSSRF.Store(false)
	close(proceed)

	res := <-done
	if res.err == nil {
		t.Fatal("redirect to internal IP was followed; expected refusal")
	}
	if !strings.Contains(res.err.Error(), "private IP") && !strings.Contains(res.err.Error(), "blocked host") {
		t.Errorf("expected SSRF-style refusal, got: %v", res.err)
	}
}

func namesOf(dets []TechDetection) []string {
	out := make([]string, 0, len(dets))
	for _, d := range dets {
		out = append(out, d.Name)
	}
	return out
}
