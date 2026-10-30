package vulnscan

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/cdp/network"
)

func cdpRequestForTest(t *testing.T, entryBytes, postData string) *network.Request {
	t.Helper()
	req := &network.Request{URL: "http://x.test/api", Method: "POST", HasPostData: true, PostData: postData}
	if entryBytes != "" {
		req.PostDataEntries = []*network.PostDataEntry{{Bytes: entryBytes}}
	}
	return req
}

func TestFormFromRequestQueryKeepsValues(t *testing.T) {
	base := &BaseRequest{Method: "GET", URL: "http://x.test/search?q=hello&page=2&q=world"}
	f, err := FormFromRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Points) != 3 {
		t.Fatalf("points = %+v", f.Points)
	}
	// Keys are sorted; duplicate occurrences keep their index.
	byName := map[string][]InjectionPoint{}
	for _, p := range f.Points {
		byName[p.Name] = append(byName[p.Name], p)
	}
	qs := byName["q"]
	if len(qs) != 2 || qs[0].Index != 0 || qs[0].Original != "hello" || qs[1].Index != 1 || qs[1].Original != "world" {
		t.Errorf("q occurrences = %+v", qs)
	}
	if pages := byName["page"]; len(pages) != 1 || pages[0].Original != "2" {
		t.Errorf("page = %+v", pages)
	}
	if f.Request == nil || string(f.Request.Body) != "" {
		t.Error("template request must survive")
	}
}

func TestFormFromRequestNestedJSON(t *testing.T) {
	body := `{"user":{"name":"ann","tags":["a","b"]},"n":3}`
	base := &BaseRequest{Method: "POST", URL: "http://x.test/api",
		HeaderValues: http.Header{"Content-Type": {"application/json"}}, Body: []byte(body)}
	f, err := FormFromRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"/user/name": "ann", "/user/tags/0": "a", "/user/tags/1": "b", "/n": "3"}
	if len(f.Points) != len(want) {
		t.Fatalf("points = %+v", f.Points)
	}
	for _, p := range f.Points {
		if want[p.Name] != p.Original {
			t.Errorf("point %q = %q, want %q", p.Name, p.Original, want[p.Name])
		}
		if p.Location != LocationJSONField {
			t.Errorf("point %q location = %s", p.Name, p.Location)
		}
	}
}

func TestMutateRequestIsolatesOneField(t *testing.T) {
	base := &BaseRequest{Method: "POST", URL: "http://x.test/submit",
		HeaderValues: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		Body:         []byte("a=1&b=2&a=3")}
	f, err := FormFromRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	var target InjectionPoint
	for _, p := range f.Points {
		if p.Name == "a" && p.Index == 1 {
			target = p
		}
	}
	req, err := MutateRequest(context.Background(), base, target, "HACK")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(req.Body)
	got := string(raw)
	if !strings.Contains(got, "a=HACK") || !strings.Contains(got, "a=1") || !strings.Contains(got, "b=2") {
		t.Errorf("siblings changed: %q", got)
	}
	// The source template is immutable.
	if string(base.Body) != "a=1&b=2&a=3" {
		t.Errorf("base mutated: %q", base.Body)
	}
}

func TestMutateJSONPointerNested(t *testing.T) {
	base := &BaseRequest{Method: "POST", URL: "http://x.test/api",
		HeaderValues: http.Header{"Content-Type": {"application/json"}},
		Body:         []byte(`{"user":{"name":"ann","id":7}}`)}
	f, err := FormFromRequest(base)
	if err != nil {
		t.Fatal(err)
	}
	var target InjectionPoint
	for _, p := range f.Points {
		if p.Name == "/user/id" {
			target = p
		}
	}
	if target.Name == "" {
		t.Fatalf("no /user/id point in %+v", f.Points)
	}
	req, err := MutateRequest(context.Background(), base, target, "8")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(raw), `"name":"ann"`) || !strings.Contains(string(raw), `"id":"8"`) {
		t.Errorf("nested mutation broke siblings: %s", raw)
	}
}

func TestMutateMissingParameterErrors(t *testing.T) {
	base := &BaseRequest{Method: "GET", URL: "http://x.test/?a=1"}
	_, err := MutateRequest(context.Background(), base, InjectionPoint{Name: "zzz", Location: LocationQueryParam}, "1")
	if err == nil {
		t.Error("expected error for unknown parameter")
	}
	incomplete := &BaseRequest{Method: "GET", URL: "http://x.test/", Incomplete: true}
	if _, err := incomplete.HTTPRequest(context.Background()); err == nil {
		t.Error("incomplete request must not build")
	}
}

func TestDecodeCDPPostBodiesBase64(t *testing.T) {
	// Real CDP semantics: entry bytes are base64.
	req := cdpRequestForTest(t, "eyJhIjoxfQ==", "")
	bodies, complete := decodeCDPPostBodies(req)
	if !complete || len(bodies) != 1 || string(bodies[0]) != `{"a":1}` {
		t.Fatalf("bodies=%q complete=%v", bodies, complete)
	}
	bad := cdpRequestForTest(t, "!!!not-base64!!!", "")
	if _, complete := decodeCDPPostBodies(bad); complete {
		t.Error("undecodable entry must mark capture incomplete")
	}
}
