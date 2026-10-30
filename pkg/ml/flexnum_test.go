package ml

import (
	"encoding/json"
	"testing"
)

// TestFileFeedbackTolerantImportance is the regression for the observed
// "cannot unmarshal number 54.0 into ... importance of type int" history
// corruption: float-encoded int fields must load cleanly and round correctly.
func TestFileFeedbackTolerantImportance(t *testing.T) {
	cases := []struct {
		name string
		json string
		imp  int
		raw  int
	}{
		{"float", `{"path":"a","importance":54.0,"raw_importance":12.0}`, 54, 12},
		{"int", `{"path":"a","importance":7,"raw_importance":3}`, 7, 3},
		{"float_round", `{"path":"a","importance":54.6,"raw_importance":2.4}`, 55, 2},
		{"missing", `{"path":"a"}`, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ff FileFeedback
			if err := json.Unmarshal([]byte(c.json), &ff); err != nil {
				t.Fatalf("unmarshal failed (regression): %v", err)
			}
			if ff.Importance != c.imp || ff.RawImportance != c.raw {
				t.Fatalf("got importance=%d raw=%d, want %d/%d", ff.Importance, ff.RawImportance, c.imp, c.raw)
			}
		})
	}
}

// TestFileFeedbackOtherFieldsPreserved guards that adding UnmarshalJSON did not
// drop the embedded-alias fields.
func TestFileFeedbackOtherFieldsPreserved(t *testing.T) {
	var ff FileFeedback
	in := `{"path":"x/y.smali","importance":9.0,"confidence":0.75,"is_app_code":true,"categories":["license"],"threat_score":4.5}`
	if err := json.Unmarshal([]byte(in), &ff); err != nil {
		t.Fatal(err)
	}
	if ff.Path != "x/y.smali" || ff.Importance != 9 || ff.Confidence != 0.75 || !ff.IsAppCode || len(ff.Categories) != 1 || ff.ThreatScore != 4.5 {
		t.Fatalf("fields not preserved: %+v", ff)
	}
}

// TestHistoryLoadWithFloatImportance is the end-to-end regression: a history
// file with a float importance must load without the "corrupt history file"
// error that previously wiped ML history.
func TestHistoryLoadWithFloatImportance(t *testing.T) {
	dir := testTempDir(t)
	path := dir + "/history.json"
	doc := `[{"top_files":[{"path":"a","importance":54.0,"raw_importance":10.0}]}]`
	if err := writeFileHelper(path, doc); err != nil {
		t.Fatal(err)
	}
	h, err := LoadHistory(path)
	if err != nil {
		t.Fatalf("LoadHistory failed (regression): %v", err)
	}
	if h == nil {
		t.Fatal("nil history")
	}
}
