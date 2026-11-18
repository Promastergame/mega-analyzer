package experts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"decisionai/s1"
)

func sourceFixture() map[string]any {
	code := ".method public static run()V\nconst-string v0, \"/sample.so\"\ninvoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V\nreturn-void\n.end method"
	sum := sha256.Sum256([]byte(code))
	digest := hex.EncodeToString(sum[:])
	return map[string]any{"source_evidence": map[string]any{
		"schema_version": 1, "static_only": true,
		"check": map[string]any{"id": "native_1", "kind": "native_load", "status": "supported", "choice": "static_call_path",
			"basis": "cfg_reaching_definitions", "scope": "retained_call_sites", "summary": "Сохранённый вызов System.load.",
			"citations": []any{map[string]any{"file": "Some.smali", "line": 12, "method": "Lsample/A;->run()V",
				"snippet": "invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V", "sha256": digest}}},
		"sources": []any{map[string]any{"file": "Some.smali", "line": 10, "method": "Lsample/A;->run()V",
			"representation": "retained_smali_method", "code": code, "sha256": digest}},
	}}
}

func sourceQuestion() s1.ExpertQuestion {
	return s1.ExpertQuestion{ID: "source_check", Task: s1.TaskSourceEvidence, Type: s1.TypeChoice,
		Options: []s1.Option{{Key: "unresolved"}, {Key: "static_call_path"}, {Key: "unreachable_call"}}}
}

func TestSourceCitationContractReturnsReviewWithoutNeuralFallback(t *testing.T) {
	state, _ := json.Marshal(sourceFixture())
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = Default(nil, nil)
	request := s1.Request{State: state, Questions: map[string]s1.Question{"source_check": {
		Type: s1.TypeChoice, Task: s1.TaskSourceEvidence, AbstainKey: "unresolved",
		Instructions: json.RawMessage(`"Inspect the supplied typed static check"`),
		Criteria:     json.RawMessage(`{"unresolved":"unknown","static_call_path":"static call","unreachable_call":"dead code"}`),
	}}}
	response, err := e.Decide(request)
	if err != nil {
		t.Fatal(err)
	}
	answer := response.Answers["source_check"]
	if answer.Source != "source-evidence-rule" || answer.Choice != "static_call_path" || answer.Route != "review" || answer.Abstained ||
		response.Backend != "experts" || len(answer.References) != 1 {
		t.Fatalf("source contract changed to an independent/automatic claim: %+v", response)
	}
	if !strings.Contains(strings.Join(answer.Evidence, " "), "Анализ потока выполнен сканером") {
		t.Fatal("scanner provenance was hidden")
	}
}

func TestSourceCitationTamperingAndIncompleteContractsAbstain(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"code", func(r map[string]any) { r["sources"].([]any)[0].(map[string]any)["code"] = "return-void" }},
		{"digest", func(r map[string]any) { r["sources"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("a", 64) }},
		{"line", func(r map[string]any) {
			r["check"].(map[string]any)["citations"].([]any)[0].(map[string]any)["line"] = 11
		}},
		{"file", func(r map[string]any) {
			r["check"].(map[string]any)["citations"].([]any)[0].(map[string]any)["file"] = "Other.smali"
		}},
		{"no_citations", func(r map[string]any) { r["check"].(map[string]any)["citations"] = []any{} }},
		{"runtime", func(r map[string]any) { r["static_only"] = false }},
		{"unknown_kind", func(r map[string]any) { r["check"].(map[string]any)["kind"] = "observed_malware_execution" }},
		{"unresolved", func(r map[string]any) {
			r["check"].(map[string]any)["status"] = "unresolved"
			r["check"].(map[string]any)["reason"] = "missing_callee"
		}},
		{"scope", func(r map[string]any) { r["check"].(map[string]any)["scope"] = "all_possible_runtime_calls" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			fixture := sourceFixture()
			change.edit(fixture["source_evidence"].(map[string]any))
			answer, handled := (SourceEvidence{}).Answer(fixture, "", sourceQuestion())
			if !handled || !answer.Abstained || len(answer.Probs) != 3 || answer.Probs[0] != 1 {
				t.Fatalf("invalid source contract did not abstain: %+v", answer)
			}
		})
	}
}

func TestSourceExpertRequiresTypedTask(t *testing.T) {
	q := sourceQuestion()
	q.Task = ""
	if _, handled := (SourceEvidence{}).Answer(sourceFixture(), "System.load definitely ran", q); handled {
		t.Fatal("free text selected the source expert")
	}
}
