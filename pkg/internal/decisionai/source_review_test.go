package decisionai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/sourceevidence"
)

func sourceReviewFixture() sourceevidence.Report {
	code := "const-string v0, \"/out.bin\"\ninvoke-direct {v9, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V"
	digest := sourceevidence.Digest(code)
	report := sourceevidence.NewReport()
	report.Sources = []sourceevidence.Source{{File: "F.smali", Line: 10, Method: "LF;->save()V", Representation: "retained_smali_method", Code: code, SHA256: digest}}
	report.Checks = []sourceevidence.Check{{ID: "file_1", Kind: "output_name", Status: "supported", Choice: "constant_filename",
		Basis: "cfg_reaching_definitions", Scope: "retained_call_sites", Summary: "constant basename",
		Citations: []sourceevidence.Citation{{File: "F.smali", Line: 10, Method: "LF;->save()V", Snippet: `const-string v0, "/out.bin"`, SHA256: digest}}}}
	return report
}

func fakeSourceResponse(t *testing.T, w http.ResponseWriter, req Request, choice string) {
	t.Helper()
	var options map[string]any
	_ = json.Unmarshal(req.Questions["source_check"].Criteria, &options)
	probabilities := map[string]float64{}
	for key := range options {
		probabilities[key] = 0
	}
	probabilities[choice] = 1
	confidence := 1.0
	_ = json.NewEncoder(w).Encode(Response{Version: "test", Backend: "experts", Answers: map[string]Answer{"source_check": {
		Type: "choice", Choice: choice, Confidence: &confidence, Probabilities: probabilities, Route: "auto", Source: "source-evidence-rule",
		References: []Reference{{Kind: "source", File: "F.smali", Line: 10, SHA256: sourceReviewFixture().Sources[0].SHA256}},
	}}})
}

func TestSourceReviewPreservesContradictoryResponsesAndOriginals(t *testing.T) {
	report := sourceReviewFixture()
	before, _ := json.Marshal(report)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		fakeSourceResponse(t, w, req, "archive_entry_name")
	}))
	defer server.Close()
	client, _ := New(server.URL, "")
	defer client.Close()
	review := ReviewSource(context.Background(), client, report, nil)
	if review.Processed != 1 || review.Consistent != 0 || review.Unresolved != 1 || review.Entries[0].ReviewRoute != "human" ||
		review.Entries[0].Response.Answers["source_check"].Choice != "archive_entry_name" {
		t.Fatalf("contradictory service answer hidden or promoted: %+v", review)
	}
	after, _ := json.Marshal(report)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("source evidence modified by model reply")
	}
}

func TestSourceReviewReusesOnlyExactSourceState(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		fakeSourceResponse(t, w, req, "constant_filename")
	}))
	defer server.Close()
	client, _ := New(server.URL, "")
	defer client.Close()
	source := sourceReviewFixture()
	first := ReviewSource(context.Background(), client, source, nil)
	second := ReviewSource(context.Background(), client, source, &first)
	if calls != 1 || second.Consistent != 1 || second.Entries[0].ReviewRoute != "review" {
		t.Fatalf("exact source response not reused: calls=%d %+v", calls, second)
	}
	source.Sources[0].Code += "\nreturn-void"
	source.Sources[0].SHA256 = sourceevidence.Digest(source.Sources[0].Code)
	source.Checks[0].Citations[0].SHA256 = source.Sources[0].SHA256
	_ = ReviewSource(context.Background(), client, source, &first)
	if calls != 2 {
		t.Fatal("changed source snapshot reused a stale response")
	}
}

func TestSourceReviewServiceFailureIsVisibleAndStopsExtraRequests(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer server.Close()
	client, _ := New(server.URL, "")
	defer client.Close()
	source := sourceReviewFixture()
	source.Checks = append(source.Checks, source.Checks[0])
	result := ReviewSource(context.Background(), client, source, nil)
	if calls != 1 || result.Status != "unavailable" || result.Processed != 0 || result.Error == "" {
		t.Fatalf("service failure hidden or repeatedly queried: %+v calls=%d", result, calls)
	}
}

func TestSourceReviewLocallyRejectedChecksRemainVisible(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		fakeSourceResponse(t, w, req, "constant_filename")
	}))
	defer server.Close()
	client, _ := New(server.URL, "")
	defer client.Close()
	source := sourceReviewFixture()
	oversized := source.Checks[0]
	oversized.ID = "oversized"
	oversized.Summary = strings.Repeat("x", 256<<10)
	source.Checks = append([]sourceevidence.Check{oversized}, source.Checks...)
	review := ReviewSource(context.Background(), client, source, nil)
	if calls != 1 || review.Total != 2 || review.Processed != 1 || review.Consistent != 1 || review.Unresolved != 1 ||
		review.Status != "partial" || review.Error != "" || len(review.Entries) != 2 {
		t.Fatalf("local rejection counted as a service response or blocked the next check: %+v calls=%d", review, calls)
	}
	if review.Entries[0].CheckID != "oversized" || review.Entries[0].ReviewRoute != "human" ||
		!strings.Contains(review.Entries[0].Reason, "256 KiB") {
		t.Fatalf("local request-limit rejection disappeared: %+v", review.Entries[0])
	}
}
