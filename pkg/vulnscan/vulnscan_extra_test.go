package vulnscan

import (
	gocrypto_hmac "crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// makeHS256 computes an HMAC-SHA256 MAC for message using key.
func makeHS256(key, message []byte) []byte {
	h := gocrypto_hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// newTestScanner builds a Scanner that points at ts.URL and bypasses the
// safety gate so active checks can run.
func newTestScanner(t *testing.T, ts *httptest.Server) *Scanner {
	t.Helper()
	s, err := NewScanner(ts.URL)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.Config.IOwnThisTarget = true
	s.Config.MaxRPS = 1000
	s.Config.Timeout = 2 * time.Second
	s.Throttle = NewPIDController(200, 1000)
	return s
}

// ─── checkCookieFlags ─────────────────────────────────────────────────────────

func TestCheckCookieFlags_MissingFlags(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session cookie with NO HttpOnly and SameSite=None (explicit weak policy)
		http.SetCookie(w, &http.Cookie{
			Name:     "PHPSESSID",
			Value:    "abc123",
			HttpOnly: false,
			Secure:   false,
			SameSite: http.SameSiteNoneMode, // explicit SameSite=None triggers COOK-003
		})
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)

	resp, err := s.Client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	vulns := s.checkCookieFlags(resp)
	ids := collectIDs(vulns)

	if !contains(ids, "WS-COOK-001") {
		t.Error("expected WS-COOK-001 (missing HttpOnly)")
	}
	// SameSite=None triggers COOK-003
	if !contains(ids, "WS-COOK-003") {
		t.Errorf("expected WS-COOK-003 (SameSite=None), got %v", ids)
	}
}

func TestCheckCookieFlags_HTTPS_MissingSecure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "tok",
			HttpOnly: true,
			Secure:   false,
		})
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s, err := NewScanner(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.Client = ts.Client()
	s.Config.IOwnThisTarget = true
	s.Throttle = NewPIDController(200, 1000)

	resp, err := s.Client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	vulns := s.checkCookieFlags(resp)
	ids := collectIDs(vulns)
	if !contains(ids, "WS-COOK-002") {
		t.Errorf("expected WS-COOK-002 (missing Secure on HTTPS), got %v", ids)
	}
}

func TestCheckCookieFlags_NoCookies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	resp, err := s.Client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	vulns := s.checkCookieFlags(resp)
	if len(vulns) != 0 {
		t.Errorf("expected no findings for response with no cookies, got %d", len(vulns))
	}
}

func TestCheckCookieFlags_SameSiteNone_SessionCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Value:    "eyJ.eyJ.sig",
			SameSite: http.SameSiteNoneMode,
		})
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	resp, err := s.Client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	vulns := s.checkCookieFlags(resp)
	ids := collectIDs(vulns)
	if !contains(ids, "WS-COOK-003") {
		t.Errorf("expected WS-COOK-003 (SameSite=None on session cookie), got %v", ids)
	}
}

// ─── isSessionCookie edge cases ───────────────────────────────────────────────

func TestIsSessionCookie_EdgeCases(t *testing.T) {
	trueNames := []string{"JSESSIONID", "ASP.NET_SessionId", "connect.sid", "csrf_token", "JWT_TOKEN"}
	for _, n := range trueNames {
		if !isSessionCookie(n) {
			t.Errorf("isSessionCookie(%q) should be true", n)
		}
	}
	falseNames := []string{"userId", "theme", "locale", "v"}
	for _, n := range falseNames {
		if isSessionCookie(n) {
			t.Errorf("isSessionCookie(%q) should be false", n)
		}
	}
}

// ─── checkCORS ────────────────────────────────────────────────────────────────

func TestCheckCORS_ArbitraryOriginReflected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCORS()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-CORS-001") {
		t.Errorf("expected WS-CORS-001 for reflected origin, got %v", ids)
	}
}

func TestCheckCORS_NullOriginAllowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCORS()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-CORS-002") {
		t.Errorf("expected WS-CORS-002 for null origin, got %v", ids)
	}
}

func TestCheckCORS_WithCredentials_Escalation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCORS()
	// severity should escalate to Critical when credentials=true
	for _, v := range vulns {
		if v.ID == "WS-CORS-001" && v.Severity != SeverityCritical {
			t.Errorf("CORS with credentials should be Critical, got %s", v.Severity)
		}
	}
}

func TestCheckCORS_WildcardWithCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCORS()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-CORS-000") {
		t.Errorf("expected WS-CORS-000 for wildcard + credentials, got %v", ids)
	}
}

func TestCheckCORS_NoVulnerability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No CORS headers at all
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCORS()
	if len(vulns) != 0 {
		t.Errorf("expected no CORS findings, got %d", len(vulns))
	}
}

// ─── checkOpenRedirect ────────────────────────────────────────────────────────

func TestCheckOpenRedirect_Detected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("redirect")
		if dest != "" {
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkOpenRedirect()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-REDIR-001") {
		t.Errorf("expected WS-REDIR-001 for open redirect, got %v", ids)
	}
}

func TestCheckOpenRedirect_NoRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkOpenRedirect()
	if len(vulns) != 0 {
		t.Errorf("expected no redirect findings, got %d", len(vulns))
	}
}

// ─── isExternalRedirect extra cases ──────────────────────────────────────────

func TestIsExternalRedirect_MoreCases(t *testing.T) {
	// Same domain with path
	if isExternalRedirect("https://example.com/path/to/page", "example.com") {
		t.Error("same-domain redirect should not be external")
	}
	// Protocol-relative
	if !isExternalRedirect("//attacker.com", "example.com") {
		t.Error("protocol-relative to different host should be external")
	}
	// Bad URL
	if isExternalRedirect("http://[invalid", "example.com") {
		t.Error("bad URL should not be flagged")
	}
}

// ─── checkCachePoisoning ──────────────────────────────────────────────────────

func TestCheckCachePoisoning_Detected(t *testing.T) {
	var poisonedHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		poisonHost := r.Header.Get("X-Forwarded-Host")
		if poisonHost != "" {
			poisonedHost = poisonHost
			w.Header().Set("X-Cache", "HIT")
			fmt.Fprintf(w, "Host: %s", poisonHost)
			return
		}
		if poisonedHost != "" {
			fmt.Fprintf(w, "Host: %s", poisonedHost)
			return
		}
		w.Write([]byte("clean response"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCachePoisoning()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-CACHE-001") {
		t.Errorf("expected WS-CACHE-001 for cache poisoning, got %v", ids)
	}
	if len(vulns) != 1 || vulns[0].Severity != SeverityHigh {
		t.Fatalf("expected one high-severity confirmed finding, got %#v", vulns)
	}
}

func TestCheckCachePoisoning_ReflectionWithoutPersistenceIsNotReported(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		poisonHost := r.Header.Get("X-Forwarded-Host")
		if poisonHost != "" {
			w.Header().Set("X-Cache", "HIT")
			fmt.Fprintf(w, "value %s", poisonHost)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCachePoisoning()
	if len(vulns) != 0 {
		t.Fatalf("reflection without a poisoned follow-up must not be reported, got %#v", vulns)
	}
}

func TestCheckCachePoisoning_NoReflection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("clean response"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkCachePoisoning()
	if len(vulns) != 0 {
		t.Errorf("expected no cache poisoning findings, got %d", len(vulns))
	}
}

// ─── checkHostHeaderInjection ─────────────────────────────────────────────────

func TestCheckHostHeaderInjection_Detected_InBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostVal := r.Header.Get("X-Forwarded-Host")
		if hostVal != "" {
			fmt.Fprintf(w, "<a href=\"http://%s/link\">click</a>", hostVal)
			return
		}
		fmt.Fprintf(w, "<a href=\"http://%s/link\">click</a>", r.Host)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkHostHeaderInjection()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-HOST-001") {
		t.Errorf("expected WS-HOST-001 for host header injection in body, got %v", ids)
	}
}

func TestCheckHostHeaderInjection_NoReflection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("safe response"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkHostHeaderInjection()
	if len(vulns) != 0 {
		t.Errorf("expected 0 findings, got %d", len(vulns))
	}
}

// ─── testCSRF ─────────────────────────────────────────────────────────────────

func TestTestCSRF_VulnerableForm(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	form := Form{
		Action: "http://example.com/transfer",
		Method: "POST",
		Inputs: []string{"amount", "to_account"},
	}
	vulns := s.testCSRF(form, nil)
	if len(vulns) == 0 {
		t.Error("expected CSRF finding for POST form with no token")
	}
	if vulns[0].ID != "WS-CSRF-001" {
		t.Errorf("expected WS-CSRF-001, got %s", vulns[0].ID)
	}
}

func TestTestCSRF_WithCSRFToken(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	form := Form{
		Action: "http://example.com/transfer",
		Method: "POST",
		Inputs: []string{"amount", "csrf_token"},
	}
	vulns := s.testCSRF(form, nil)
	if len(vulns) != 0 {
		t.Errorf("expected no CSRF finding when csrf_token is present, got %d", len(vulns))
	}
}

func TestTestCSRF_GetMethod_Skipped(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	form := Form{Action: "http://example.com/search", Method: "GET", Inputs: []string{"q"}}
	vulns := s.testCSRF(form, nil)
	if len(vulns) != 0 {
		t.Error("GET forms should not generate CSRF findings")
	}
}

func TestTestCSRF_SameSiteProtection(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	form := Form{
		Action: "http://example.com/delete",
		Method: "POST",
		Inputs: []string{"id"},
	}
	// SameSite=Strict session cookie provides protection
	cookies := []string{"PHPSESSID=abc; SameSite=Strict"}
	vulns := s.testCSRF(form, cookies)
	if len(vulns) != 0 {
		t.Errorf("SameSite=Strict should protect against CSRF, got %d findings", len(vulns))
	}
}

func TestTestCSRF_XSRFToken(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	form := Form{
		Action: "http://example.com/action",
		Method: "POST",
		Inputs: []string{"data", "_xsrf"},
	}
	vulns := s.testCSRF(form, nil)
	if len(vulns) != 0 {
		t.Errorf("_xsrf token should prevent CSRF finding, got %d", len(vulns))
	}
}

// ─── probeSensitiveFiles ──────────────────────────────────────────────────────

func TestProbeSensitiveFiles_EnvFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(200)
			w.Write([]byte("APP_KEY=secret\nDB_PASSWORD=hunter2"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.probeSensitiveFiles()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-SENS-001") {
		t.Errorf("expected WS-SENS-001 for .env file, got %v", ids)
	}
}

func TestProbeSensitiveFiles_GitHEAD(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.WriteHeader(200)
			w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.probeSensitiveFiles()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-SENS-002") {
		t.Errorf("expected WS-SENS-002 for .git/HEAD, got %v", ids)
	}
}

func TestProbeSensitiveFiles_NothingFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.probeSensitiveFiles()
	if len(vulns) != 0 {
		t.Errorf("expected no findings for 404 responses, got %d", len(vulns))
	}
}

func TestProbeSensitiveFiles_RobotsTxt(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(200)
			w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /internal\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.probeSensitiveFiles()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-SENS-010") {
		t.Errorf("expected WS-SENS-010 for robots.txt, got %v", ids)
	}
}

func TestProbeSensitiveFiles_SQLDump(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dump.sql" {
			w.WriteHeader(200)
			w.Write([]byte("CREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);"))
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.probeSensitiveFiles()
	ids := collectIDs(vulns)
	if !contains(ids, "WS-SENS-004") {
		t.Errorf("expected WS-SENS-004 for SQL dump, got %v", ids)
	}
}

// ─── analyzeJWTPayload ────────────────────────────────────────────────────────

func TestAnalyzeJWTPayload_SensitiveFields(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	// Build a JWT with "role" and "email" in payload
	payload := map[string]interface{}{"sub": "1234", "email": "user@example.com", "role": "admin"}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	token := "eyJhbGciOiJIUzI1NiJ9." + payloadB64 + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	vulns := s.analyzeJWTPayload(token)
	ids := collectIDs(vulns)
	if !contains(ids, "WS-JWT-001") {
		t.Errorf("expected WS-JWT-001 for sensitive JWT fields, got %v", ids)
	}
}

func TestAnalyzeJWTPayload_NoSensitiveFields(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	payload := map[string]interface{}{"sub": "1234", "iat": 1516239022}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	token := "eyJhbGciOiJIUzI1NiJ9." + payloadB64 + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	vulns := s.analyzeJWTPayload(token)
	if len(vulns) != 0 {
		t.Errorf("expected no findings for non-sensitive payload, got %d", len(vulns))
	}
}

func TestAnalyzeJWTPayload_InvalidBase64(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	// Payload part is not valid base64
	vulns := s.analyzeJWTPayload("eyJhbGciOiJIUzI1NiJ9.!!!notbase64!!!.sig")
	if len(vulns) != 0 {
		t.Error("invalid base64 payload should produce no findings")
	}
}

// ─── checkJWTNoneAlg ──────────────────────────────────────────────────────────

func TestCheckJWTNoneAlg_Vulnerable(t *testing.T) {
	// Server rejects a tampered signature (baseline) but blindly trusts alg:none.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")
		headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if strings.Contains(string(headerRaw), `"alg":"none"`) {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)

	// Construct a valid-ish JWT with HS256 header and a real payload
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","admin":false}`))
	token := header + "." + payload + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	vulns := s.checkJWTNoneAlg(token)
	if len(vulns) == 0 {
		t.Error("expected WS-JWT-002 when server rejects a bad signature but accepts alg:none")
	}
}

func TestCheckJWTNoneAlg_NotGatedByAuth(t *testing.T) {
	// Server returns 200 regardless of the token — it isn't actually gating on
	// this JWT, so accepting alg:none is not evidence of a real vulnerability.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","admin":false}`))
	token := header + "." + payload + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	vulns := s.checkJWTNoneAlg(token)
	if len(vulns) != 0 {
		t.Errorf("expected no finding when baseline (bad signature) also returns 200, got %d", len(vulns))
	}
}

func TestCheckJWTNoneAlg_InvalidHeader(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	// Non-base64 header
	vulns := s.checkJWTNoneAlg("!!!.payload.sig")
	if len(vulns) != 0 {
		t.Error("invalid header base64 should return empty")
	}
}

// ─── checkJWTWeakSecret ───────────────────────────────────────────────────────

func TestCheckJWTWeakSecret_Cracked(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	// Build a JWT signed with the weak secret "password123"
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","iat":1700000000}`))
	message := hdr + "." + pl
	mac := makeHS256([]byte("password123"), []byte(message))
	sig := base64.RawURLEncoding.EncodeToString(mac)
	token := message + "." + sig

	// Wordlist with the right secret
	wordlist, err := os.CreateTemp("", "jwt-words-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(wordlist.Name())
	wordlist.WriteString("notthissecret\npassword123\n")
	wordlist.Close()

	s.Config.JWTWordlist = wordlist.Name()
	vulns := s.checkJWTWeakSecret(token)
	ids := collectIDs(vulns)
	if !contains(ids, "WS-JWT-003") {
		t.Errorf("expected WS-JWT-003 for weak secret, got %v", ids)
	}
}

func TestCheckJWTWeakSecret_NoWordlist(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)
	s.Config.JWTWordlist = "" // no wordlist configured

	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
	vulns := s.checkJWTWeakSecret(token)
	if len(vulns) != 0 {
		t.Error("no wordlist should return empty")
	}
}

func TestCheckJWTWeakSecret_NonHS_Alg(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	wl, _ := os.CreateTemp("", "wl*.txt")
	wl.WriteString("secret\n")
	wl.Close()
	defer os.Remove(wl.Name())
	s.Config.JWTWordlist = wl.Name()

	// RS256 token — offline cracking not applicable
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	token := header + "." + payload + ".sig"

	vulns := s.checkJWTWeakSecret(token)
	if len(vulns) != 0 {
		t.Error("RS256 tokens should not be brute-forced")
	}
}

func TestCheckJWTWeakSecret_MissingWordlistFile(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)
	s.Config.JWTWordlist = "/does/not/exist/wordlist.txt"
	s.LogFunc = func(string) {} // suppress log output

	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
	vulns := s.checkJWTWeakSecret(token)
	if len(vulns) != 0 {
		t.Error("missing wordlist file should return empty")
	}
}

// ─── checkJWTs (integration) ──────────────────────────────────────────────────

func TestCheckJWTs_FromAuthHeader(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Embed JWT with email in payload in body
		payload, _ := json.Marshal(map[string]interface{}{"sub": "1", "email": "a@b.com"})
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		bodyToken := hdr + "." + encoded + ".sig"
		w.Header().Set("Authorization", "Bearer "+token)
		fmt.Fprintf(w, `{"token":"%s"}`, bodyToken)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	s := newTestScanner(t, ts)
	body := `{"token":"eyJhbGciOiJIUzI1NiJ9.` + base64.RawURLEncoding.EncodeToString([]byte(`{"email":"x@y.com"}`)) + `.sig"}`
	vulns := s.checkJWTs(resp, body)
	// Should find payload with email field
	found := false
	for _, v := range vulns {
		if v.ID == "WS-JWT-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected WS-JWT-001 from JWT with email in payload; vulns=%v", collectIDs(vulns))
	}
}

func TestCheckJWTs_FromCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// JWT with admin: true in payload
		payload, _ := json.Marshal(map[string]interface{}{"sub": "1", "admin": true})
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		cookieToken := hdr + "." + encoded + ".sig"
		http.SetCookie(w, &http.Cookie{Name: "jwt", Value: cookieToken})
		w.WriteHeader(200)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	s := newTestScanner(t, ts)
	vulns := s.checkJWTs(resp, "")
	ids := collectIDs(vulns)
	if !contains(ids, "WS-JWT-001") {
		t.Errorf("expected WS-JWT-001 from JWT in cookie; got %v", ids)
	}
}

// ─── testHPP ─────────────────────────────────────────────────────────────────

func TestTestHPP_Concatenation_Detected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Concatenate multiple q values
		vals := r.URL.Query()["q"]
		w.Write([]byte(strings.Join(vals, ",")))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	form := Form{
		Action: ts.URL,
		Method: "GET",
		Inputs: []string{"q"},
	}
	vulns := s.testHPP(form)
	ids := collectIDs(vulns)
	if !contains(ids, "WS-HPP-001") {
		t.Errorf("expected WS-HPP-001 for HPP concatenation, got %v", ids)
	}
}

func TestTestHPP_NoVulnerability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just return a safe response
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	form := Form{
		Action: ts.URL,
		Method: "GET",
		Inputs: []string{"name"},
	}
	vulns := s.testHPP(form)
	if len(vulns) != 0 {
		t.Errorf("expected no HPP findings for safe response, got %d", len(vulns))
	}
}

func TestTestHPP_POST_NoVulnerability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	form := Form{
		Action: ts.URL,
		Method: "POST",
		Inputs: []string{"username", "email"},
	}
	vulns := s.testHPP(form)
	if len(vulns) != 0 {
		t.Errorf("expected 0 HPP findings for POST, got %d", len(vulns))
	}
}

func TestTestHPP_SkipsNonHTTP(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.Throttle = NewPIDController(200, 1000)

	form := Form{
		Action: "http://example.com/action",
		Method: "PUT",
		Inputs: []string{"data"},
	}
	vulns := s.testHPP(form)
	if len(vulns) != 0 {
		t.Errorf("PUT method should return no HPP findings, got %d", len(vulns))
	}
}

// ─── ScannerConfig / DefaultScannerConfig ─────────────────────────────────────

func TestDefaultScannerConfig(t *testing.T) {
	cfg := DefaultScannerConfig()
	if cfg.MaxWorkers != 4 {
		t.Errorf("MaxWorkers = %d, want 4", cfg.MaxWorkers)
	}
	if cfg.UserAgent == "" {
		t.Error("UserAgent should not be empty")
	}
	if cfg.MaxRPS <= 0 {
		t.Errorf("MaxRPS = %d, should be > 0", cfg.MaxRPS)
	}
	if cfg.Timeout <= 0 {
		t.Errorf("Timeout = %v, should be > 0", cfg.Timeout)
	}
}

// ─── PIDController extra cases ────────────────────────────────────────────────

func TestPIDController_LowRPS(t *testing.T) {
	// MaxRPS=1 is the lowest safe positive value (zero causes a divide-by-zero in NewPIDController)
	pid := NewPIDController(200, 1)
	pid.Wait()
	pid.Observe(10 * time.Millisecond)
	if d := pid.Delay(); d < 0 {
		t.Errorf("delay should be >= 0, got %v", d)
	}
}

func TestPIDController_MaxDelayClamp(t *testing.T) {
	pid := NewPIDController(200, 1)
	// Simulate very slow RTT to push delay to max
	for i := 0; i < 20; i++ {
		pid.Observe(10 * time.Second)
	}
	if d := pid.Delay(); d > 5*time.Second+10*time.Millisecond {
		t.Errorf("delay should be clamped to 5s, got %v", d)
	}
}

// ─── NewScanner edge cases ────────────────────────────────────────────────────

func TestNewScanner_SchemelessURL(t *testing.T) {
	// URL without scheme should get http:// prepended
	s, err := NewScanner("example.com")
	if err != nil {
		t.Fatalf("schemeless URL should be accepted: %v", err)
	}
	if !strings.HasPrefix(s.Target, "http") {
		t.Errorf("target should have http scheme, got %q", s.Target)
	}
}

// ─── ParseCurlCommand more coverage ──────────────────────────────────────────

func TestParseCurlCommand_Flags(t *testing.T) {
	cases := []struct {
		cmd   string
		check func(*CurlRequest) bool
		desc  string
	}{
		{
			cmd:   `curl -X DELETE https://api.example.com/resource/1`,
			check: func(r *CurlRequest) bool { return r.Method == "DELETE" },
			desc:  "DELETE method",
		},
		{
			cmd:   `curl --insecure https://self-signed.com`,
			check: func(r *CurlRequest) bool { return r.Insecure },
			desc:  "--insecure flag",
		},
		{
			cmd:   `curl -u admin:pass https://api.example.com`,
			check: func(r *CurlRequest) bool { return r.Headers["Authorization"] == "Basic admin:pass" },
			desc:  "basic auth via -u",
		},
		{
			cmd:   `curl -A "MyAgent/1.0" https://api.example.com`,
			check: func(r *CurlRequest) bool { return r.Headers["User-Agent"] == "MyAgent/1.0" },
			desc:  "user-agent via -A",
		},
		{
			cmd:   `curl -b "session=abc" https://api.example.com`,
			check: func(r *CurlRequest) bool { return strings.Contains(r.Headers["Cookie"], "session=abc") },
			desc:  "cookie via -b",
		},
		{
			cmd:   `curl -d '{"key":"val"}' https://api.example.com`,
			check: func(r *CurlRequest) bool { return r.Method == "POST" && r.Body == `{"key":"val"}` },
			desc:  "POST body auto-switch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			r, err := ParseCurlCommand(tc.cmd)
			if err != nil {
				t.Fatalf("%s: %v", tc.desc, err)
			}
			if !tc.check(r) {
				t.Errorf("%s: check failed on request %+v", tc.desc, r)
			}
		})
	}
}

func TestParseCurlCommand_EmptyCommand(t *testing.T) {
	// A command with no URL should return an error
	_, err := ParseCurlCommand(`curl -X POST`)
	if err == nil {
		t.Error("curl command with no URL should return error")
	}
}

// ─── ExportVulnAsCurl edge cases ─────────────────────────────────────────────

func TestExportVulnAsCurl_WithHeaders(t *testing.T) {
	v := Vulnerability{URL: "https://example.com/api", Parameter: "id", Payload: "1"}
	out := ExportVulnAsCurl(v, "PUT", map[string]string{"Authorization": "Bearer tok"}, `{"id":1}`)
	if !strings.Contains(out, "Authorization") {
		t.Error("expected Authorization header in curl export")
	}
}

// ─── isJWT edge cases ─────────────────────────────────────────────────────────

func TestIsJWT_EdgeCases(t *testing.T) {
	// starts with eyJ but only 2 parts
	if isJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0") {
		t.Error("2-part token starting with eyJ should not be JWT")
	}
	// 3 parts but doesn't start with eyJ
	if isJWT("abc.def.ghi") {
		t.Error("3-part token not starting with eyJ should not be JWT")
	}
	// valid JWT
	if !isJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") {
		t.Error("valid 3-part eyJ token should be JWT")
	}
}

// ─── helper functions ─────────────────────────────────────────────────────────

func collectIDs(vulns []Vulnerability) []string {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	return ids
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ─── sensitiveProbe.detectFunc coverage ──────────────────────────────────────

func TestSensitiveProbe_DetectFunctions(t *testing.T) {
	// Test each detectFunc directly
	for _, probe := range defaultSensitiveProbes {
		t.Run(probe.name, func(t *testing.T) {
			// Negative case: 404 should never trigger
			ok, _ := probe.detectFunc(404, "", http.Header{})
			if ok {
				t.Errorf("probe %s: should not trigger on 404", probe.id)
			}
		})
	}
}

func TestSensitiveProbe_EnvTrigger(t *testing.T) {
	// Find the .env probe
	for _, probe := range defaultSensitiveProbes {
		if probe.path == "/.env" {
			ok, ev := probe.detectFunc(200, "APP_KEY=secret\nDB_HOST=localhost", http.Header{})
			if !ok {
				t.Error(".env probe should trigger for APP_ content")
			}
			if ev == "" {
				t.Error("evidence should not be empty")
			}
			return
		}
	}
	t.Error(".env probe not found")
}

func TestSensitiveProbe_GitConfig(t *testing.T) {
	for _, probe := range defaultSensitiveProbes {
		if probe.path == "/.git/config" {
			ok, _ := probe.detectFunc(200, "[core]\n\trepositoryformatversion = 0", http.Header{})
			if !ok {
				t.Error(".git/config probe should trigger for [core] content")
			}
			return
		}
	}
	t.Error(".git/config probe not found")
}

func TestSensitiveProbe_BackupZip(t *testing.T) {
	for _, probe := range defaultSensitiveProbes {
		if probe.path == "/backup.zip" {
			h := http.Header{}
			h.Set("Content-Type", "application/zip")
			ok, _ := probe.detectFunc(200, "", h)
			if !ok {
				t.Error("backup.zip probe should trigger for zip Content-Type")
			}
			return
		}
	}
	t.Error("/backup.zip probe not found")
}

func TestSensitiveProbe_GraphQL(t *testing.T) {
	for _, probe := range defaultSensitiveProbes {
		if strings.Contains(probe.path, "graphql") {
			ok, _ := probe.detectFunc(200, `{"data":{"__schema":{"types":[]}}}`, http.Header{})
			if !ok {
				t.Error("graphql probe should trigger for __schema response")
			}
			return
		}
	}
	t.Error("graphql probe not found")
}

func TestSensitiveProbe_CrossdomainXML(t *testing.T) {
	for _, probe := range defaultSensitiveProbes {
		if probe.path == "/crossdomain.xml" {
			body := `<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`
			ok, _ := probe.detectFunc(200, body, http.Header{})
			if !ok {
				t.Error("crossdomain.xml probe should trigger for wildcard domain")
			}
			return
		}
	}
	t.Error("/crossdomain.xml probe not found")
}

// ─── isExternalRedirect with protocol-relative same domain ───────────────────

func TestIsExternalRedirect_SameDomainWWW(t *testing.T) {
	// www.example.com stripping
	if isExternalRedirect("https://www.example.com/ok", "example.com") {
		t.Error("www.example.com should not be flagged as external for example.com")
	}
}

// ─── log function ─────────────────────────────────────────────────────────────

func TestScannerLog_NilFunc(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.LogFunc = nil
	// Should not panic
	s.log("test %s %d", "msg", 42)
}

func TestScannerLog_WithFunc(t *testing.T) {
	var captured string
	s, _ := NewScanner("http://example.com")
	s.LogFunc = func(msg string) { captured = msg }
	s.log("hello %s", "world")
	if captured != "hello world" {
		t.Errorf("LogFunc received %q, want 'hello world'", captured)
	}
}

// ─── URL builder in Scanner ───────────────────────────────────────────────────

func TestNewScanner_ParsedURL(t *testing.T) {
	s, err := NewScanner("https://api.example.com:8443/v1")
	if err != nil {
		t.Fatal(err)
	}
	if s.BaseURL.Scheme != "https" {
		t.Errorf("scheme = %q, want https", s.BaseURL.Scheme)
	}
	if s.BaseURL.Host != "api.example.com:8443" {
		t.Errorf("host = %q", s.BaseURL.Host)
	}
	parsed, _ := url.Parse(s.Target)
	if parsed.Path != "/v1" {
		t.Errorf("path = %q, want /v1", parsed.Path)
	}
}
