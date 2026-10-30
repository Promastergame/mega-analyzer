package labtest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"mega-analyzer/pkg/ncer"
)

// TestAdminBackdoorPatternFeedsNcer proves the ncer wiring itself: a request
// that carries a hardcoded "magic header" bypass -- the same CWE-798 shape
// used by labs/servers/go/admin-backdoor-header -- is recorded as an HTTP
// exchange plus an authority mismatch (a grant for "user" login vs. an
// observed "admin_action" with no matching grant), and Reconcile() accepts
// it without error. Unlike the live-mode tests below, this is fully
// self-contained (an inline httptest handler, not an import of the separate
// lab module) so it always runs, with no docker-compose lab required.
func TestAdminBackdoorPatternFeedsNcer(t *testing.T) {
	const backdoorHeader = "X-Debug-Role"
	const backdoorValue = "admin"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(backdoorHeader) == backdoorValue {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"dashboard":"top secret admin data"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/admin/dashboard", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set(backdoorHeader, backdoorValue)

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (backdoor should have granted access): %s", resp.StatusCode, body)
	}

	now := time.Now().UnixMilli()
	c := ncer.NewCollector(time.Now())
	c.ObserveHTTP(http.MethodGet, srv.URL+"/api/admin/dashboard", strconv.Itoa(resp.StatusCode), "", "")

	// The caller was only ever granted a "user" login -- never an admin
	// authority -- yet the observed action is an admin-only one. This is
	// the authority-grant vs. authority-observed mismatch the Rust
	// authority binder (bind_authority) is designed to flag.
	authEvents := ncer.FromAuthorityContextGranular(ncer.AuthorityContext{
		Subject:  ncer.Subject{ID: "lab-client", Kind: "http-client", Name: "lab test client"},
		Identity: ncer.Identity{Principal: "anonymous", Issuer: "lab"},
		Granted: []ncer.GrantedPermission{
			{Name: "role:user", Scope: "normal", Source: "login"},
		},
		Observed: []ncer.ObservedAction{
			{Action: "admin_dashboard_access", Target: "/api/admin/dashboard", TimestampMs: now},
		},
	}, "labtest.admin-backdoor", now)
	c.ObserveAuthority(authEvents)

	if c.Len() != 1 {
		t.Fatalf("ncer collector recorded %d HTTP events, want 1", c.Len())
	}

	// Reconcile() returns (nil, nil) in the default stub build (no Rust FFI
	// linked) -- same expectation as every other pkg/ncer test in this
	// repo. The point here is that it does not error on real backdoor
	// traffic, not that a specific DiscrepancyVector score comes back.
	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
}

// liveAdminBackdoorServer describes one of the real "hidden admin without
// login" lab servers under labs/servers/, and the exact exploit request that
// should grant admin access with zero prior authentication.
type liveAdminBackdoorServer struct {
	name    string
	addr    string // host:port
	request func() (*http.Request, error)
}

var liveAdminBackdoorServers = []liveAdminBackdoorServer{
	{
		name: "admin-backdoor-header",
		addr: "127.0.0.1:18001",
		request: func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18001/api/admin/dashboard", nil)
			if err == nil {
				req.Header.Set("X-Debug-Role", "admin")
			}
			return req, err
		},
	},
	{
		name: "admin-jwt-none",
		addr: "127.0.0.1:18002",
		request: func() (*http.Request, error) {
			// {"alg":"none","typ":"JWT"} . {"sub":"attacker","role":"admin","exp":9999999999} . <empty signature>
			const forgedToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
				".eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0" +
				"."
			req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18002/api/admin/dashboard", nil)
			if err == nil {
				req.Header.Set("Authorization", "Bearer "+forgedToken)
			}
			return req, err
		},
	},
	{
		name: "admin-hidden-debug",
		addr: "127.0.0.1:18006",
		request: func() (*http.Request, error) {
			return http.NewRequest(http.MethodGet, "http://127.0.0.1:18006/_internal/become-admin?key=CHANGE_ME_LAB_DEBUG_KEY", nil)
		},
	},
}

// TestLiveAdminBackdoorServers drives the real exploit request against each
// actually-running lab server (started via `docker compose -f
// docker-compose.yml -f labs/servers/docker-compose.lab.yml up`, or `go run`
// per-server) and feeds the resulting traffic into ncer. Any server that
// isn't reachable is skipped rather than failed, since this repo doesn't
// require the lab to be running for `go test ./...` to pass.
func TestLiveAdminBackdoorServers(t *testing.T) {
	for _, srv := range liveAdminBackdoorServers {
		srv := srv
		t.Run(srv.name, func(t *testing.T) {
			if !reachable(srv.addr, 300*time.Millisecond) {
				t.Skipf("%s not reachable at %s -- start labs/servers (docker-compose.lab.yml) to run this test live", srv.name, srv.addr)
			}

			req, err := srv.request()
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("request to %s failed: %v", srv.name, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status = %d, want 200 (exploit should grant admin access): %s", srv.name, resp.StatusCode, body)
			}

			c := ncer.NewCollector(time.Now())
			c.ObserveHTTP(req.Method, req.URL.String(), strconv.Itoa(resp.StatusCode), "", "")
			if _, err := c.Reconcile(); err != nil {
				t.Fatalf("%s: ncer Reconcile: %v", srv.name, err)
			}
		})
	}
}
