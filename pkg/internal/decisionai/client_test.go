package decisionai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func noulRequest() Request {
	return Request{State: json.RawMessage(`{"rule_id":"secret/test"}`), Questions: map[string]Question{
		"fp": {Type: "noul", Instructions: json.RawMessage(`"False positive?"`)},
	}}
}

const noulResponse = `{"version":"1.17.0","backend":"experts","model":"test","answers":{"fp":{"type":"noul","noul":0.8,"route":"review","source":"finding-rule","evidence":["rule_id"]}}}`

func TestNormalizeURL(t *testing.T) {
	for raw, want := range map[string]string{
		"http://localhost:7480/": "http://127.0.0.1:7480",
		"https://127.0.0.1":      "https://127.0.0.1",
		"http://[::1]:7480":      "http://[::1]:7480",
	} {
		got, err := NormalizeURL(raw)
		if err != nil || got != want {
			t.Fatalf("%s: %s, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "file:///tmp/model", "http://example.com", "http://192.168.1.1", "http://127.0.0.1@evil.test", "http://user:private@127.0.0.1", "http://127.0.0.1/x", "http://127.0.0.1?token=private", "http://127.0.0.1#private", "http://127.0.0.1:65536", "http://localhost.evil.test", "http://127.0.0.1/%2e%2e"} {
		_, err := NormalizeURL(raw)
		if err == nil {
			t.Errorf("accepted %s", raw)
		}
		if err != nil && strings.Contains(err.Error(), "private") {
			t.Errorf("credential included in error")
		}
	}
}

func TestDecideWireAndZeroValue(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer local-test" {
			t.Errorf("wrong request: %s %s", r.Method, r.URL.Path)
		}
		if _, err := ReadRequest(r.Body); err != nil {
			t.Error(err)
		}
		fmt.Fprint(w, strings.Replace(noulResponse, "0.8", "0", 1))
	}))
	defer s.Close()
	c, err := New(s.URL, "local-test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.Decide(context.Background(), noulRequest())
	if err != nil {
		t.Fatal(err)
	}
	if r.Answers["fp"].Noul == nil || *r.Answers["fp"].Noul != 0 {
		t.Fatal("valid zero was lost")
	}
}

func TestRejectInvalidResponses(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         `{}`,
		"missing":       strings.Replace(noulResponse, `"noul":0.8,`, "", 1),
		"null":          strings.Replace(noulResponse, `"noul":0.8`, `"noul":null`, 1),
		"out-of-range":  strings.Replace(noulResponse, "0.8", "1.2", 1),
		"wrong-type":    strings.Replace(noulResponse, `"type":"noul"`, `"type":"choice"`, 1),
		"wrong-id":      strings.Replace(noulResponse, `"fp":`, `"other":`, 1),
		"wrong-route":   strings.Replace(noulResponse, `"route":"review"`, `"route":"execute"`, 1),
		"multiple-json": noulResponse + `{}`,
		"oversized":     strings.Repeat(" ", MaxResponseBytes) + noulResponse,
	} {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer s.Close()
			c, _ := New(s.URL, "")
			defer c.Close()
			out, err := c.Decide(context.Background(), noulRequest())
			if err == nil || out.Answers != nil {
				t.Fatal("malformed response treated as a decision")
			}
		})
	}
}

func TestChoiceDistribution(t *testing.T) {
	req := Request{State: json.RawMessage(`"test"`), Questions: map[string]Question{"role": {Type: "choice", Instructions: json.RawMessage(`"Role?"`), Criteria: json.RawMessage(`{"boolean":"Boolean","unknown":"Unknown"}`)}}}
	for _, body := range []string{
		`{"type":"choice","choice":"undeclared","probabilities":{"boolean":0.8,"unknown":0.2},"confidence":0.6,"route":"review"}`,
		`{"type":"choice","choice":"boolean","probabilities":{"boolean":0.8,"unknown":0.8},"confidence":0.6,"route":"review"}`,
		`{"type":"choice","choice":"boolean","probabilities":{"boolean":0.8,"unknown":-0.2},"confidence":0.6,"route":"review"}`,
	} {
		var a Answer
		_ = json.Unmarshal([]byte(body), &a)
		if err := validateResponse(req, Response{Version: "1", Backend: "test", Answers: map[string]Answer{"role": a}}); err == nil {
			t.Fatal("invalid distribution accepted")
		}
	}
}

func TestScoreUsesDeclaredScale(t *testing.T) {
	req := Request{State: json.RawMessage(`"state"`), Questions: map[string]Question{"level": {Type: "score", Instructions: json.RawMessage(`"Level?"`), Criteria: json.RawMessage(`{"10":"low","20":"high"}`)}}}
	score, confidence := 15.0, 0.0
	r := Response{Version: "1", Backend: "test", Answers: map[string]Answer{"level": {Type: "score", Score: &score, Confidence: &confidence, Route: "human", Probabilities: map[string]float64{"10": 0.5, "20": 0.5}}}}
	if err := validateResponse(req, r); err != nil {
		t.Fatal(err)
	}
	score = 21
	if err := validateResponse(req, r); err == nil {
		t.Fatal("score outside declared scale accepted")
	}
}

func TestNoRedirectOrErrorBodyLeak(t *testing.T) {
	var requests atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer dest.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", dest.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		fmt.Fprint(w, "private scan content")
	}))
	defer s.Close()
	c, _ := New(s.URL, "test-token")
	defer c.Close()
	_, err := c.Decide(context.Background(), noulRequest())
	if err == nil || requests.Load() != 0 || strings.Contains(err.Error(), "private") {
		t.Fatalf("redirect/error leaked: %v", err)
	}
	if c.http.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy must be disabled")
	}
}

func TestCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer s.Close()
	c, _ := New(s.URL, "")
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Decide(ctx, noulRequest()); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestReadRequest(t *testing.T) {
	for _, raw := range []string{`{"state":null,"questions":{}}`, `{"state":"x","questions":{},"unexpected":true}`, strings.Repeat(" ", MaxRequestBytes+1)} {
		if _, err := ReadRequest(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	b, _ := json.Marshal(noulRequest())
	if _, err := ReadRequest(strings.NewReader(string(b) + ` {}`)); err == nil {
		t.Fatal("trailing input accepted")
	}
}
