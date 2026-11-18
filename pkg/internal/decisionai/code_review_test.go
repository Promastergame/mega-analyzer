package decisionai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/sourceevidence"
)

func TestNeuralRoleRejectsProbabilityWhenNoInferenceRan(t *testing.T) {
	source := sourceevidence.Source{SHA256: strings.Repeat("a", 64)}
	answer := Answer{Type: "choice", Source: "smalirole-neural", Route: "human", Abstained: true,
		Reason: "reference_role_outside_taxonomy", Neural: &NeuralInference{SchemaVersion: 1, Task: NeuralRoleTask,
			Status: "skipped", Reason: "reference_role_outside_taxonomy", Architecture: "relational_gcn",
			Scope: NeuralRoleScope, FeatureSchema: "smalirole-def-use-v1", InputSHA256: source.SHA256, TargetLine: 3, Threshold: .8}}
	if err := validateNeuralRole(answer, source, 3); err != nil {
		t.Fatalf("an honest coverage skip was rejected: %v", err)
	}
	confidence := 1.0
	answer.Choice, answer.Probabilities, answer.Confidence = "unknown", map[string]float64{"unknown": 1}, &confidence
	if err := validateNeuralRole(answer, source, 3); err == nil {
		t.Fatal("an invented 100% unknown result was accepted without a forward pass")
	}
}

func TestCodeReviewContinuesAfterHTTPNeuralSkip(t *testing.T) {
	code := ".method static a()V\n.registers 2\nconst/4 v0, 0x0\ninvoke-static {v0}, LA;->consume(Ljava/lang/Object;)V\nconst/4 v1, 0x1\nsput-boolean v1, LA;->flag:Z\nreturn-void\n.end method"
	source := sourceevidence.NewReport()
	source.Sources = []sourceevidence.Source{{File: "smali/A.smali", Method: "LA;->a()V", Line: 40,
		Representation: "retained_smali_method", Code: code, SHA256: sourceevidence.Digest(code)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var input Request
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var state struct{ Line int }
		if err := json.Unmarshal(input.State, &state); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		a := Answer{Type: "choice", Source: "smalirole-neural", Route: "human", Abstained: true,
			Reason: "reference_role_outside_taxonomy", Neural: &NeuralInference{SchemaVersion: 1, Task: NeuralRoleTask,
				Status: "skipped", Reason: "reference_role_outside_taxonomy", Architecture: "relational_gcn", Scope: NeuralRoleScope,
				FeatureSchema: "smalirole-def-use-v1", ModelSHA256: strings.Repeat("a", 64), InputSHA256: sourceevidence.Digest(code),
				TargetLine: state.Line, Threshold: .8}}
		usage := json.RawMessage(`{"model_calls":0,"cache_hits":0}`)
		if state.Line == 5 {
			confidence := 1.0
			a.Choice, a.Confidence, a.Route, a.Abstained, a.Reason = "boolean", &confidence, "review", false, ""
			a.Probabilities = map[string]float64{}
			for _, label := range neuralRoleLabels {
				a.Probabilities[label] = 0
			}
			a.Probabilities["boolean"] = 1
			a.Neural.Status, a.Neural.Reason, a.Neural.ForwardPasses, a.Neural.GraphNodes, a.Neural.GraphEdges = "predicted", "", 1, 4, 6
			usage = json.RawMessage(`{"model_calls":1,"cache_hits":0}`)
		}
		_ = json.NewEncoder(w).Encode(Response{Version: "fixture", Backend: "experts", Usage: usage, Answers: map[string]Answer{"literal_role": a}})
	}))
	defer server.Close()
	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	report := ReviewCodeRoles(context.Background(), client, source, 128)
	if report.Error != "" || report.Processed != 2 || report.Inferred != 1 || report.Skipped != 1 || report.Failed != 0 || report.NotProcessed != 0 {
		t.Fatalf("HTTP abstention interrupted the remaining code review: %+v", report)
	}
	if report.Entries[0].Status != "skipped" || report.Entries[0].Response.Answers["literal_role"].Choice != "" ||
		report.Entries[1].Status != "predicted" || report.Entries[1].Response.Answers["literal_role"].Choice != "boolean" {
		t.Fatal("skip and actual prediction were not retained separately")
	}
}

func TestCodeReviewRequiresNeuralInputAndProvenance(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "wrong_source"}[corrupt], func(t *testing.T) {
			code := ".method static a()Z\n.registers 1\nconst/4 v0, 0x1\nreturn v0\n.end method"
			source := sourceevidence.NewReport()
			source.Sources = []sourceevidence.Source{{File: "smali/A.smali", Method: "LA;->a()Z", Line: 40, Representation: "retained_smali_method", Code: code, SHA256: sourceevidence.Digest(code)}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var input Request
				if json.NewDecoder(req.Body).Decode(&input) != nil {
					t.Error("bad request")
					w.WriteHeader(400)
					return
				}
				var state map[string]any
				_ = json.Unmarshal(input.State, &state)
				if len(state) != 3 || state["code"] != code || input.Questions["literal_role"].Task != NeuralRoleTask {
					t.Error("scanner conclusions or wrong task supplied to neural model")
				}
				p := map[string]float64{}
				for _, label := range neuralRoleLabels {
					p[label] = 0
				}
				p["boolean"] = 1
				confidence := 1.0
				digest := sourceevidence.Digest(code)
				if corrupt {
					digest = strings.Repeat("b", 64)
				}
				_ = json.NewEncoder(w).Encode(Response{Version: "fixture", Backend: "experts", Answers: map[string]Answer{"literal_role": {
					Type: "choice", Choice: "boolean", Confidence: &confidence, Probabilities: p, Source: "smalirole-neural", Route: "review",
					Neural: &NeuralInference{SchemaVersion: 1, Task: NeuralRoleTask, Status: "predicted", Architecture: "relational_gcn", Scope: NeuralRoleScope,
						ModelSHA256: strings.Repeat("a", 64), InputSHA256: digest, FeatureSchema: "smalirole-def-use-v1", TargetLine: 3, GraphNodes: 4, GraphEdges: 6, ForwardPasses: 1, Threshold: .8}}}})
			}))
			defer server.Close()
			client, err := New(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			report := ReviewCodeRoles(context.Background(), client, source, 128)
			if report.Processed != 1 || len(report.Entries) != 1 || report.Entries[0].Line != 42 {
				t.Fatalf("method-relative line lost: %+v", report)
			}
			if corrupt {
				if report.Inferred != 0 || report.Failed != 1 || report.Entries[0].Response.Answers["literal_role"].Neural.InputSHA256 != strings.Repeat("b", 64) {
					t.Fatal("inconsistent response accepted or discarded")
				}
			} else if report.Inferred != 1 || report.Failed != 0 {
				t.Fatalf("valid neural response lost: %+v", report)
			}
		})
	}
}
