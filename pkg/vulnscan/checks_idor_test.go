package vulnscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// idorLab serves per-user objects: /doc?id=N returns the owner's document,
// 403 for other users' documents when enforced. Identity arrives through the
// Authorization header the gateway injects, so no transport stub is needed:
// missing credentials default to ann, the primary test user.
func idorLab(enforce bool) *httptest.Server {
	owners := map[string]string{"1": "ann", "2": "bob"}
	userOf := func(r *http.Request) string {
		switch r.Header.Get("Authorization") {
		case "Bearer bob-token":
			return "bob"
		default:
			return "ann"
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := userOf(r)
		id := r.URL.Query().Get("id")
		owner, ok := owners[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if enforce && owner != user {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"owner":%q,"secret":%q}`, id, owner, "secret-"+id)
	}))
}

func idorForm(srv *httptest.Server) Form {
	base := &BaseRequest{Method: "GET", URL: srv.URL + "/doc?id=1"}
	f, err := FormFromRequest(base)
	if err != nil {
		panic(err)
	}
	return f
}

func TestIDORCrossRoleProven(t *testing.T) {
	srv := idorLab(false) // broken access control
	defer srv.Close()
	s, err := NewScanner(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.IOwnThisTarget = true
	s.Config.AuthBearer = "ann-token"
	s.Config.AuthBearer2 = "bob-token"

	form := idorForm(srv)
	form.Action = srv.URL + "/doc"
	vulns := s.testIDOR(form)
	if len(vulns) != 1 {
		t.Fatalf("vulns = %+v", vulns)
	}
	v := vulns[0]
	if v.Severity != SeverityHigh || v.Verification != "cross-role" {
		t.Errorf("vuln = %+v, want High cross-role proof", v)
	}
	if len(v.InteractionIDs) != 2 {
		t.Errorf("interaction IDs = %v, want both role probes", v.InteractionIDs)
	}
}

func TestIDOREnforcedIsQuiet(t *testing.T) {
	srv := idorLab(true) // correct access control
	defer srv.Close()
	s, err := NewScanner(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.IOwnThisTarget = true
	s.Config.AuthBearer = "ann-token"
	s.Config.AuthBearer2 = "bob-token"

	if vulns := s.testIDOR(idorForm(srv)); len(vulns) != 0 {
		t.Errorf("enforced control must be quiet: %+v", vulns)
	}
}

func TestIDORSingleIdentityIsHeuristic(t *testing.T) {
	srv := idorLab(false)
	defer srv.Close()
	s, err := NewScanner(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.IOwnThisTarget = true

	vulns := s.testIDOR(idorForm(srv))
	if len(vulns) != 1 {
		t.Fatalf("vulns = %+v", vulns)
	}
	if vulns[0].Severity != SeverityMedium || vulns[0].Verification != "heuristic-only" {
		t.Errorf("single-identity verdict must stay a Medium heuristic: %+v", vulns[0])
	}
}
