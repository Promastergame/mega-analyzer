package web

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScanLinesAnyBreakSplitsCarriageReturns is the regression test for the log
// that only appeared once the scan had finished.
//
// Progress bars terminate each redraw with \r and print \n only at the very end.
// The stock bufio.ScanLines splitter therefore buffered thousands of redraws
// into a single token that was released all at once, so the browser saw nothing
// during the run and then received one enormous concatenated blob.
func TestScanLinesAnyBreakSplitsCarriageReturns(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader("first\rsecond\r\nthird\nfourth"))
	sc.Split(scanLinesAnyBreak)

	var got []string
	for sc.Scan() {
		got = append(got, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	want := []string{"first", "second", "third", "fourth"}
	if len(got) != len(want) {
		t.Fatalf("got %d tokens %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestIsProgressLine pins down what may be collapsed. Throttling drops
// intermediate redraws, so a false positive here would silently discard real
// log output — the matcher must ignore a bare percentage.
func TestIsProgressLine(t *testing.T) {
	progress := []string{
		"99% [20821/21000]  scan_and_analyze",
		"scan_and_analyze \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 50%",
		"[1/100]",
		"progress ==========",
	}
	for _, s := range progress {
		if !isProgressLine(s) {
			t.Errorf("should be treated as a progress redraw: %q", s)
		}
	}

	normal := []string{
		"Coverage: 87% of classes analysed",
		"Loaded 21000 methods",
		"[INFO] starting scan",
		"Done.",
		"Found 3 issues (100% confidence)",
	}
	for _, s := range normal {
		if isProgressLine(s) {
			t.Errorf("real log line must never be collapsed: %q", s)
		}
	}
}

// TestHTTPErrorJSONForAPI keeps machine callers parseable: the front-end reads
// these bodies, so an API path must not receive an HTML page.
func TestHTTPErrorJSONForAPI(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stop/abc", nil)
	httpError(rec, req, http.StatusNotFound, "No job with that id is running.")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got, ok := body["status"].(float64); !ok || int(got) != 404 {
		t.Errorf("status field = %v, want 404", body["status"])
	}
	if body["path"] != "/api/stop/abc" {
		t.Errorf("path field = %v", body["path"])
	}
}

// TestHTTPErrorHTMLForBrowser also guards the format string. errorPageHTML
// carries six verbs and literal %% sequences in its CSS; a miscount would ship
// a page containing "%!d(MISSING)" instead of failing loudly at build time.
func TestHTTPErrorHTMLForBrowser(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	httpError(rec, req, http.StatusNotFound, "No page is served at this address.")

	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want HTML", ct)
	}
	if strings.Contains(body, "%!") {
		t.Errorf("format verb mismatch in errorPageHTML; rendered: %s", body)
	}
	for _, want := range []string{"404", "Not Found", "Back to dashboard", "/nope", "width:100%;"} {
		if !strings.Contains(body, want) {
			t.Errorf("error page missing %q", want)
		}
	}
}

// TestRequireMethodRejectsGet covers the hardening: a stray GET must not be able
// to trigger a state change, and the 405 must advertise Allow.
func TestRequireMethodRejectsGet(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stop/abc", nil)

	if requireMethod(rec, req, http.MethodPost) {
		t.Fatal("GET should not be allowed on a POST-only endpoint")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}

	ok := httptest.NewRecorder()
	if !requireMethod(ok, httptest.NewRequest(http.MethodPost, "/api/stop/abc", nil), http.MethodPost) {
		t.Error("POST should be allowed")
	}
}

// Collapsing progress redraws has a server half (the "event: progress" frames
// emitted by the SSE handler) and a browser half (the listener that overwrites
// the last row instead of appending). Nothing links them at compile time, so
// renaming one side would silently bring the log spam back.
func TestProgressStreamHalvesStayInSync(t *testing.T) {
	for _, want := range []string{
		`addEventListener("` + progressEventName + `"`, // browser subscribes
		"function lp(txt)", // in-place renderer
		`"ll lp"`,          // row carries the .lp class
		".lp{",             // and the class is styled
	} {
		if !strings.Contains(webUIHTML, want) {
			t.Errorf("served page is missing %q", want)
		}
	}
}

// TestBrandLogoIsEmbeddedPNG guards the sidebar logo. The mark is a 3.3 KB
// base64 blob sitting inside the page template, which is exactly the kind of
// thing an editor, a merge, or a careless reflow truncates without anyone
// noticing: the page still renders and the <img> just silently shows nothing.
// Decoding it here turns a quiet visual regression into a hard failure.
func TestBrandLogoIsEmbeddedPNG(t *testing.T) {
	const marker = `src="data:image/png;base64,`

	i := strings.Index(webUIHTML, marker)
	if i < 0 {
		t.Fatal("brand logo data URI is missing from webUIHTML")
	}
	rest := webUIHTML[i+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatal("brand logo data URI is never closed")
	}

	raw, err := base64.StdEncoding.DecodeString(rest[:end])
	if err != nil {
		t.Fatalf("brand logo base64 does not decode: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) {
		head := raw
		if len(head) > 8 {
			head = head[:8]
		}
		t.Fatalf("brand logo payload is not a PNG, starts with %x", head)
	}
	if len(raw) < 2000 {
		t.Fatalf("brand logo payload is only %d bytes, expected the full 64x64 icon", len(raw))
	}

	// The <img> needs the class the stylesheet sizes it with. Without it the
	// raw 64px bitmap escapes the 34px logo plate.
	if !strings.Contains(webUIHTML, `class="lg-mark"`) {
		t.Error(`brand logo <img> lost its class="lg-mark"`)
	}
	if !strings.Contains(webUIHTML, ".logo .lg-mark{") {
		t.Error("stylesheet lost the .logo .lg-mark sizing rule")
	}
}
