package api

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// helpers shared across pentest handler tests
func pentestServer() *APIServer { return NewAPIServer(19100) }

func postJSON(s *APIServer, handler func(http.ResponseWriter, *http.Request), body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func getReq(s *APIServer, handler func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// ─── handleCORSCheck ─────────────────────────────────────────────────────────

func TestHandleCORSCheck_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleCORSCheck)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCORSCheck_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCORSCheck, "not json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleCORSCheck_MissingURL_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCORSCheck, `{"url":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleCORSCheck_PrivateIP(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCORSCheck, `{"url":"http://127.0.0.1/api"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleCORSCheck_LocalhostSSRF(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCORSCheck, `{"url":"http://localhost/api"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ─── handleOpenRedirect ───────────────────────────────────────────────────────

func TestHandleOpenRedirect_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleOpenRedirect)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleOpenRedirect_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleOpenRedirect, "{bad}")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleOpenRedirect_MissingURL_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleOpenRedirect, `{"url":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleOpenRedirect_PrivateIP(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleOpenRedirect, `{"url":"http://192.168.1.1/"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ─── handleDirScan ────────────────────────────────────────────────────────────

func TestHandleDirScan_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleDirScan)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleDirScan_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleDirScan, "{{")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDirScan_MissingURL_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleDirScan, `{"url":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDirScan_PrivateIP(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleDirScan, `{"url":"http://10.0.0.1/"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ─── handleTechDetect ────────────────────────────────────────────────────────

func TestHandleTechDetect_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleTechDetect)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleTechDetect_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleTechDetect, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleTechDetect_MissingURL_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleTechDetect, `{"url":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleTechDetect_PrivateIP(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleTechDetect, `{"url":"http://172.16.0.1/"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ─── handleCookieAudit ───────────────────────────────────────────────────────

func TestHandleCookieAudit_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleCookieAudit)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCookieAudit_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCookieAudit, "garbage")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleCookieAudit_MissingURL_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCookieAudit, `{"url":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleCookieAudit_PrivateIP(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleCookieAudit, `{"url":"http://192.168.0.1/"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ─── handleSubdomainEnum ─────────────────────────────────────────────────────

func TestHandleSubdomainEnum_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleSubdomainEnum)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSubdomainEnum_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleSubdomainEnum, "!!!")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSubdomainEnum_MissingDomain_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleSubdomainEnum, `{"domain":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSubdomainEnum_PrivateIP(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleSubdomainEnum, `{"domain":"127.0.0.1"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleSubdomainEnum_WordlistTooLarge_2(t *testing.T) {
	s := pentestServer()
	wordlist := make([]string, 10001)
	for i := range wordlist {
		wordlist[i] = "sub"
	}
	body := `{"domain":"example.com","wordlist":[` + strings.Repeat(`"a",`, 10000) + `"b"]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleSubdomainEnum(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized wordlist, got %d", w.Code)
	}
}

// ─── handlePortScan ──────────────────────────────────────────────────────────

func TestHandlePortScan_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handlePortScan)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandlePortScan_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handlePortScan, "{bad json}")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePortScan_MissingHost_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handlePortScan, `{"host":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePortScan_PrivateHost(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handlePortScan, `{"host":"127.0.0.1","ports":[80]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ─── handleSSLAudit ──────────────────────────────────────────────────────────

func TestHandleSSLAudit_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleSSLAudit)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSSLAudit_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleSSLAudit, "bad")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSSLAudit_MissingHost_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleSSLAudit, `{"host":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSSLAudit_PrivateHost(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleSSLAudit, `{"host":"127.0.0.1","port":443}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ─── handleHostInfo ──────────────────────────────────────────────────────────

func TestHandleHostInfo_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleHostInfo)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleHostInfo_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleHostInfo, "xyz")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleHostInfo_MissingTarget_2(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleHostInfo, `{"target":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleHostInfo_PrivateTarget(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleHostInfo, `{"target":"10.0.0.1"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ─── handleScanWeb ────────────────────────────────────────────────────────────

func TestHandleScanWeb_MethodNotAllowed_2(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleScanWeb)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleScanWeb_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleScanWeb, "{{{{")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ─── handleScanAPK ────────────────────────────────────────────────────────────

func TestHandleScanAPK_MethodNotAllowed_2(t *testing.T) {
	s := pentestServer()
	w := getReq(s, s.handleScanAPK)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── grabBanner ──────────────────────────────────────────────────────────────

func TestGrabBanner_PrivateHost(t *testing.T) {
	result := grabBanner("127.0.0.1", 80, 200*1e6)
	_ = result
}

func TestGrabBanner_InvalidHost(t *testing.T) {
	result := grabBanner("invalid.host.that.does.not.exist.xyz", 9999, 100*1e6)
	_ = result
}

// ─── handleScanWeb with SSRF body ────────────────────────────────────────────

func TestHandleScanWeb_PrivateIPSSRF(t *testing.T) {
	s := pentestServer()
	body := bytes.NewBufferString(`{"target":"http://127.0.0.1/","i_own_this_target":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/scan", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleScanWeb(w, req)
	// Should be forbidden due to SSRF check
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for private IP scan target")
	}
}

// ─── handleMITMStart input validation ────────────────────────────────────────

func TestHandleMITMStart_MethodNotAllowed(t *testing.T) {
	s := pentestServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	s.handleMITMStart(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleMITMStart_InvalidJSON(t *testing.T) {
	s := pentestServer()
	w := postJSON(s, s.handleMITMStart, "not-json")
	// handleMITMStart ignores JSON parse errors and uses defaults
	_ = w
}

func TestHandleTechDetect_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	// Start local mock HTTP server that simulates detected headers/technologies
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Header().Set("Server", "Apache/2.4")
		w.Write([]byte(`<html><script src="/wp-content/themes/twentytwenty/script.js"></script></html>`))
	}))
	defer ts.Close()

	s := pentestServer()
	body := `{"url":"` + ts.URL + `"}`
	w := postJSON(s, s.handleTechDetect, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCookieAudit_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	// Mock HTTP server setting cookies with varied parameters
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "secret_value",
			HttpOnly: false, // insecure flag
			Secure:   false, // insecure flag
		})
	}))
	defer ts.Close()

	s := pentestServer()
	body := `{"url":"` + ts.URL + `"}`
	w := postJSON(s, s.handleCookieAudit, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleSubdomainEnum_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	s := pentestServer()
	body := `{"domain":"example.com"}`
	w := postJSON(s, s.handleSubdomainEnum, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandlePortScan_ScanningMockServer(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	// Start local TCP mock listener
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	s := pentestServer()
	// Split host and port
	urlStr := ts.URL
	urlStr = strings.TrimPrefix(urlStr, "http://")
	parts := strings.Split(urlStr, ":")
	host := parts[0]
	port := 80
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &port)
	}

	body := fmt.Sprintf(`{"host":"%s","ports":[%d]}`, host, port)
	w := postJSON(s, s.handlePortScan, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCORSCheck_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := pentestServer()
	body := fmt.Sprintf(`{"url":"%s"}`, ts.URL)
	w := postJSON(s, s.handleCORSCheck, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleOpenRedirect_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := pentestServer()
	body := fmt.Sprintf(`{"url":"%s"}`, ts.URL)
	w := postJSON(s, s.handleOpenRedirect, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleDirScan_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test.php" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := pentestServer()
	body := fmt.Sprintf(`{"url":"%s","wordlist":["test.php"],"concurrency":2}`, ts.URL)
	w := postJSON(s, s.handleDirScan, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleSSLAudit_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	// Parse host/port
	u := ts.URL
	u = strings.TrimPrefix(u, "https://")
	host, portStr, _ := net.SplitHostPort(u)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	s := pentestServer()
	body := fmt.Sprintf(`{"host":"%s","port":%d}`, host, port)
	w := postJSON(s, s.handleSSLAudit, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestHandleHostInfo_HappyPath(t *testing.T) {
	isTestingBypassSSRF.Store(true)
	defer func() { isTestingBypassSSRF.Store(false) }()

	s := pentestServer()
	body := `{"target":"127.0.0.1"}`
	w := postJSON(s, s.handleHostInfo, body)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
