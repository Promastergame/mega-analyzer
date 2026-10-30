package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// workflowLab is a two-user lab: /login issues a session cookie and a token,
// /item requires a session and echoes the owner, /obj/<id> is per-user data.
func workflowLab() *httptest.Server {
	sessions := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login" && r.Method == http.MethodPost:
			_ = r.ParseForm()
			user := r.Form.Get("user")
			if user == "" {
				http.Error(w, "missing user", http.StatusBadRequest)
				return
			}
			sid := "sid-" + user
			sessions[sid] = user
			http.SetCookie(w, &http.Cookie{Name: "session", Value: sid, Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok-" + user, "user": user})
		case r.URL.Path == "/item" && r.Method == http.MethodPost:
			c, err := r.Cookie("session")
			if err != nil {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			user, ok := sessions[c.Value]
			if !ok {
				http.Error(w, "auth", http.StatusForbidden)
				return
			}
			_ = r.ParseForm()
			fmt.Fprintf(w, `{"owner":%q,"item":%q}`, user, r.Form.Get("name"))
		default:
			http.NotFound(w, r)
		}
	}))
}

func testScannerFor(t *testing.T, target string) *Scanner {
	t.Helper()
	s, err := NewScanner(target)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.IOwnThisTarget = true
	return s
}

func TestRunWorkflowLoginCreateRead(t *testing.T) {
	srv := workflowLab()
	defer srv.Close()
	s := testScannerFor(t, srv.URL)

	wf := FSMWorkflow{Name: "create-as-ann", States: []FSMState{
		{Method: "POST", URL: srv.URL + "/login", Data: map[string]string{"user": "ann"},
			ExtractVars: map[string]string{"token": "json:/token"}},
		{Method: "POST", URL: srv.URL + "/item", Data: map[string]string{"name": "widget", "tok": "{{token}}"},
			ExtractVars: map[string]string{"owner": `regex:"owner":"([^"]+)"`}},
	}}
	result := s.RunWorkflow(context.Background(), wf)
	if result.Error != "" || !result.Succeeded || result.StepsOK != 2 {
		t.Fatalf("result = %+v", result)
	}
	if result.Vars["token"] != "tok-ann" || result.Vars["owner"] != "ann" {
		t.Errorf("vars = %v", result.Vars)
	}
	if len(result.Interactions) != 2 {
		t.Errorf("interactions = %v, want 2 recorded", result.Interactions)
	}
	if got := s.Ledger.FindByCheck("fsm:create-as-ann"); len(got) != 2 {
		t.Errorf("ledger has %d fsm interactions, want 2", len(got))
	}
}

func TestRunWorkflowRolesAreIsolated(t *testing.T) {
	srv := workflowLab()
	defer srv.Close()
	s := testScannerFor(t, srv.URL)

	wf := FSMWorkflow{Name: "roles", States: []FSMState{
		{Method: "POST", URL: srv.URL + "/login", Data: map[string]string{"user": "ann"}, Role: "A",
			ExtractVars: map[string]string{"a_owner": `regex:"user":"([^"]+)"`}},
		{Method: "POST", URL: srv.URL + "/login", Data: map[string]string{"user": "bob"}, Role: "B",
			ExtractVars: map[string]string{"b_owner": `regex:"user":"([^"]+)"`}},
		{Method: "POST", URL: srv.URL + "/item", Data: map[string]string{"name": "a-item"}, Role: "A",
			ExtractVars: map[string]string{"a_item_owner": `regex:"owner":"([^"]+)"`}},
		{Method: "POST", URL: srv.URL + "/item", Data: map[string]string{"name": "b-item"}, Role: "B",
			ExtractVars: map[string]string{"b_item_owner": `regex:"owner":"([^"]+)"`}},
	}}
	result := s.RunWorkflow(context.Background(), wf)
	if result.Error != "" || !result.Succeeded {
		t.Fatalf("result = %+v", result)
	}
	if result.Vars["a_item_owner"] != "ann" || result.Vars["b_item_owner"] != "bob" {
		t.Errorf("role cookies leaked across identities: %v", result.Vars)
	}
}

func TestRunWorkflowExtractorsAndAssertions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Mode", "lab")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	s := testScannerFor(t, srv.URL)

	ok := s.RunWorkflow(context.Background(), FSMWorkflow{Name: "ex", States: []FSMState{
		{Method: "GET", URL: srv.URL + "/", ExpectStatus: 201,
			ExtractVars: map[string]string{"st": "status", "mode": "header:X-Mode", "flag": "json:/ok"}},
	}})
	if ok.Error != "" || !ok.Succeeded {
		t.Fatalf("result = %+v", ok)
	}
	if ok.Vars["st"] != "201" || ok.Vars["mode"] != "lab" || ok.Vars["flag"] != "true" {
		t.Errorf("vars = %v", ok.Vars)
	}

	bad := s.RunWorkflow(context.Background(), FSMWorkflow{Name: "bad", States: []FSMState{
		{Method: "GET", URL: srv.URL + "/", ExpectStatus: 200},
	}})
	if bad.Error == "" || bad.Succeeded {
		t.Errorf("status assertion must fail: %+v", bad)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	c := s.RunWorkflow(cancelled, FSMWorkflow{Name: "c", States: []FSMState{{Method: "GET", URL: srv.URL + "/"}}})
	if c.Error == "" {
		t.Errorf("cancelled run must report: %+v", c)
	}
}

func TestReplayDoesNotTouchNetwork(t *testing.T) {
	srv := workflowLab()
	defer srv.Close()
	s := testScannerFor(t, srv.URL)

	wf := FSMWorkflow{Name: "rec", States: []FSMState{
		{Method: "POST", URL: srv.URL + "/login", Data: map[string]string{"user": "ann"}},
	}}
	if result := s.RunWorkflow(context.Background(), wf); result.Error != "" {
		t.Fatal(result.Error)
	}
	// Kill the lab: replay must serve from the recording, never dial out.
	srv.Close()

	replay := s.ReplayClient("fsm:rec")
	// NOTE: replay matches the recorded URL exactly, so rebuild it from history.
	exchanges := SnapshotExchanges(s.Ledger, "fsm:rec")
	if len(exchanges) != 1 {
		t.Fatalf("exchanges = %d", len(exchanges))
	}
	rereq, _ := http.NewRequest(http.MethodPost, exchanges[0].URL, strings.NewReader("user=ann"))
	rereq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := replay.Do(rereq)
	if err != nil {
		t.Fatalf("replay miss: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("replay status = %d", resp.StatusCode)
	}

	unknown, _ := http.NewRequest(http.MethodGet, exchanges[0].URL+"/nope", nil)
	if _, err := replay.Do(unknown); err == nil {
		t.Error("unknown request must fail offline, never hit the network")
	}
}

func TestGatewayRecordsBoundedBodies(t *testing.T) {
	big := strings.Repeat("x", 2<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, big)
	}))
	defer srv.Close()
	s := testScannerFor(t, srv.URL)

	req, _ := http.NewRequestWithContext(WithCheckID(context.Background(), "big"), http.MethodGet, srv.URL, nil)
	resp, err := s.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	found := s.Ledger.FindByCheck("big")
	if len(found) != 1 {
		t.Fatalf("recorded = %d", len(found))
	}
	if len(found[0].Body) > (256 << 10) {
		t.Errorf("recorded body %d bytes exceeds gateway bound", len(found[0].Body))
	}
	if len(found[0].Tags) == 0 || found[0].Tags[0] != http.MethodGet {
		t.Errorf("tags = %v", found[0].Tags)
	}
}
