package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"decisionai/s1"
)

func collectServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "votes.jsonl")
	collectFeedbackPath = path
	t.Cleanup(func() { collectFeedbackPath = "" })
	eng := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	srv := httptest.NewServer(Handler(eng, "tok", true))
	t.Cleanup(srv.Close)
	return srv, path
}

func postCollect(t *testing.T, srv *httptest.Server, tok, body string) int {
	t.Helper()
	rq, _ := http.NewRequest("POST", srv.URL+"/v1/collect/feedback", strings.NewReader(body))
	rq.Header.Set("Authorization", "Bearer "+tok)
	rq.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

func voteBody(sha string, vote int, src string) string {
	return `{"img_sha256":"` + sha + `","width":1400,"height":933,"box":{"class":"blood_dark","x":880,"y":261,"w":137,"h":104},"vote":` + itoaTest(vote) + `,"src":"` + src + `"}`
}

func itoaTest(n int) string {
	if n < 0 {
		return "-1"
	}
	return "1"
}

func TestCollectPageAndFeedback(t *testing.T) {
	srv, path := collectServer(t)
	// Страница отдаётся.
	rq, _ := http.NewRequest("GET", srv.URL+"/collect", nil)
	res, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("page: %d", res.StatusCode)
	}
	for _, want := range []string{"fitImage", "paste", "loadFile", "/v1/collect/feedback", "/v1/see"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("page misses %q", want)
		}
	}
	sha := strings.Repeat("ab", 32)
	if c := postCollect(t, srv, "bad", voteBody(sha, 1, "auto")); c != 401 {
		t.Fatalf("token: %d", c)
	}
	if c := postCollect(t, srv, "tok", `{"img_sha256":"zz","width":10,"height":10,"box":{"class":"blood_dark","x":0,"y":0,"w":1,"h":1},"vote":1,"src":"auto"}`); c != 400 {
		t.Fatalf("bad sha: %d", c)
	}
	if c := postCollect(t, srv, "tok", strings.Replace(voteBody(sha, 1, "auto"), "blood_dark", "alien", 1)); c != 400 {
		t.Fatalf("bad class: %d", c)
	}
	if c := postCollect(t, srv, "tok", voteBody(sha, -1, "auto")); c != 200 {
		t.Fatalf("dislike: %d", c)
	}
	// Twenty-five distinct active positive regions fit; the next is rejected.
	for i := 0; i < 25; i++ {
		if c := postCollect(t, srv, "tok", strings.Replace(voteBody(sha, 1, "auto"), `"x":880`, fmt.Sprintf(`"x":%d`, 880+i), 1)); c != 200 {
			t.Fatalf("like %d: %d", i, c)
		}
	}
	if c := postCollect(t, srv, "tok", strings.Replace(voteBody(sha, 1, "auto"), `"x":880`, `"x":920`, 1)); c != 409 {
		t.Fatalf("like budget: %d", c)
	}
	// А дизлайки дальше идут.
	if c := postCollect(t, srv, "tok", voteBody(sha, -1, "auto")); c != 200 {
		t.Fatalf("dislike after budget: %d", c)
	}
	b, _ := os.ReadFile(path)
	if lines := strings.Count(string(b), "\n"); lines != 27 {
		t.Fatalf("want 27 votes, got %d: %q", lines, b)
	}
}

func TestCustomCollectClass(t *testing.T) {
	for _, label := range []string{"custom:волосы", "custom:clothing", "custom:кожа руки"} {
		if !validCustomCollectClass(label) {
			t.Errorf("valid custom class rejected: %q", label)
		}
	}
	for _, label := range []string{"alien", "custom:", "custom: test", "custom:test\n", "custom:" + strings.Repeat("я", 65)} {
		if validCustomCollectClass(label) {
			t.Errorf("invalid custom class accepted: %q", label)
		}
	}
	f := collectFeedback{ImgSHA256: strings.Repeat("ab", 32), Width: 10, Height: 10, Box: collectBox{Class: "custom:волосы", X: 0, Y: 0, W: 5, H: 5}, Vote: 1, Src: "hint"}
	if err := f.validate(); err != nil {
		t.Fatal(err)
	}
	f.Src = "auto"
	if err := f.validate(); err == nil {
		t.Fatal("custom class must be manual-only")
	}
}

func TestCollectBudgetAndCustomHint(t *testing.T) {
	srv, _ := collectServer(t)
	sha := strings.Repeat("cd", 32)
	body := strings.Replace(voteBody(sha, 1, "hint"), "blood_dark", "custom:волосы", 1)
	if c := postCollect(t, srv, "tok", body); c != 200 {
		t.Fatalf("custom hint: %d", c)
	}
	rq, _ := http.NewRequest("GET", srv.URL+"/v1/collect/budget?sha="+sha, nil)
	rq.Header.Set("Authorization", "Bearer tok")
	res, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(b), `"likes":1`) {
		t.Fatalf("budget: %d %s", res.StatusCode, b)
	}
}
