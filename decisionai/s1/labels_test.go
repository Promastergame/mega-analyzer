package s1

import (
	"encoding/json"
	"testing"
)

func TestLabelsRejectNullAndInvalidDistributions(t *testing.T) {
	for _, tc := range []struct{ typ, label string }{
		{TypeNoul, "null"}, {TypeNoul, ""}, {TypeNoul, "2"},
		{TypeChoice, "null"}, {TypeChoice, `{"a":null,"b":1}`},
		{TypeChoice, `{"a":-1,"b":2}`}, {TypeChoice, `{"a":1e308,"b":1e308}`},
		{TypeChoice, `{"unknown":1}`}, {TypeChoice, `{}`},
	} {
		if _, err := targetFor(Answer{Type: tc.typ, keys: []string{"a", "b"}}, json.RawMessage(tc.label)); err == nil {
			t.Errorf("accepted %s label %q", tc.typ, tc.label)
		}
	}
	for _, label := range []string{"true", "false", "0", "1", "0.4"} {
		if _, err := targetFor(Answer{Type: TypeNoul}, json.RawMessage(label)); err != nil {
			t.Errorf("rejected valid label %s: %v", label, err)
		}
	}
}

func TestCompleteLabelsRequired(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	l := Labelled{Request: req(t, `{"state":"ready","questions":{"q":{"type":"noul","instructions":"Ready?"}}}`), Labels: map[string]json.RawMessage{}}
	if err := e.ValidateLabelled(l); err == nil {
		t.Fatal("missing label accepted")
	}
	l.Labels["unknown"] = json.RawMessage(`true`)
	if err := e.ValidateLabelled(l); err == nil {
		t.Fatal("unknown label accepted")
	}
	delete(l.Labels, "unknown")
	l.Labels["q"] = json.RawMessage(`null`)
	if rep := e.Evaluate([]Labelled{l}); rep.Questions != 0 || len(rep.Errors) != 1 {
		t.Fatalf("invalid example included in quality metrics: %+v", rep)
	}
}

func TestEvalFailureReportAndConfidenceInterval(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	r := req(t, `{"state":"ready","questions":{"q":{"type":"noul","instructions":"Ready?"}}}`)
	prediction, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	// Pick the opposite of the actual backend answer; verify the whole reporting path.
	label := `true`
	if *prediction.Answers["q"].Noul >= 0.5 {
		label = `false`
	}
	l := Labelled{Group: "my-project", Request: r, Labels: map[string]json.RawMessage{"q": json.RawMessage(label)}}
	rep := e.Evaluate([]Labelled{l})
	if len(rep.Failures) != 1 {
		t.Fatalf("failures: %+v", rep)
	}
	f := rep.Failures[0]
	if f.Example != 1 || f.Group != l.Group || f.Question != "q" || f.Expected != label || f.Expected == f.Predicted || f.Source == "" {
		t.Fatalf("wrong failure details: %+v", f)
	}
	if rep.BySource[f.Source].N != 1 || rep.Confusion[TypeNoul][f.Expected][f.Predicted] != 1 {
		t.Fatalf("wrong source or confusion counts: %+v", rep)
	}
	m := rep.ByType[TypeNoul]
	if m.Agreement != 0 || m.AgreementLow != 0 || m.AgreementHigh < 0.79 || m.AgreementHigh > 0.80 {
		t.Fatalf("unexpected Wilson interval: %+v", m)
	}
}
