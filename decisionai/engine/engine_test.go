package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

const sample = ".method public static limit()I\n.registers 1\nconst/16 v0, 10\nreturn v0\n.end method"

func req() Request {
	return Request{ID: "test", Code: sample, Scope: "test_fixture", Meta: Meta{AppOwned: true}, State: map[string]any{}}
}
func TestStateQuestionTrueWhenFalseWhen(t *testing.T) {
	q := Question{Text: "ready?", TrueWhen: []Condition{{"ready", "eq", true}}, FalseWhen: []Condition{{"ready", "eq", false}}}
	for _, tc := range []struct {
		name  string
		state map[string]any
		want  string
	}{{"true", map[string]any{"ready": true}, "true"}, {"false", map[string]any{"ready": false}, "false"}, {"missing", map[string]any{}, "unknown"}, {"type", map[string]any{"ready": "true"}, "unknown"}} {
		t.Run(tc.name, func(t *testing.T) {
			a := AnswerQuestion(tc.state, q)
			if a.State != tc.want {
				t.Fatalf("%+v", a)
			}
		})
	}
	q.FalseWhen = q.TrueWhen
	if a := AnswerQuestion(map[string]any{"ready": true}, q); a.State != "conflict" {
		t.Fatal(a)
	}
}
func TestConditionOperators(t *testing.T) {
	s := map[string]any{"n": json.Number("10"), "nested": map[string]any{"ok": true}, "null": nil}
	for _, c := range []Condition{{"n", "gt", 9.0}, {"n", "gte", 10.0}, {"n", "lt", 11.0}, {"n", "lte", 10.0}, {"n", "eq", 10.0}, {"n", "ne", 11.0}, {"n", "in", []any{10.0, 20.0}}, {"nested.ok", "eq", true}, {"missing", "exists", false}, {"null", "exists", true}} {
		got, _ := condition(s, c)
		if got != 1 {
			t.Errorf("%+v => %d", c, got)
		}
	}
}
func TestUnknownBranchDoesNotApprove(t *testing.T) {
	q := Question{Text: "q", TrueWhen: []Condition{{"x", "eq", true}}, FalseWhen: []Condition{{"missing", "eq", true}}}
	if AnswerQuestion(map[string]any{"x": true}, q).State != "unknown" {
		t.Fatal("missing opposing context must remain unknown")
	}
}
func TestThreshold(t *testing.T) {
	r := req()
	for _, v := range []float64{-1, 1.1, math.NaN(), math.Inf(1)} {
		r.Threshold = &Thresholds{v, .8}
		if _, e := Analyze(r, nil, nil); e == nil {
			t.Fatal(v)
		}
	}
	r.Threshold = &Thresholds{.45, .7}
	out, e := Analyze(r, nil, nil)
	if e != nil || !out.Finding.AboveThreshold {
		t.Fatalf("%+v %v", out, e)
	}
	r.Threshold.Finding = .451
	out, _ = Analyze(r, nil, nil)
	if out.Finding.AboveThreshold {
		t.Fatal("threshold boundary")
	}
}
func TestPartialSmaliValidation(t *testing.T) {
	tests := []struct{ name, code, want string }{{"valid", sample, "preflight_pass"}, {"bad_v", strings.ReplaceAll(sample, "v0", "v5"), "fail"}, {"bad_const4", strings.Replace(sample, "const/16 v0, 10", "const/4 v0, 10", 1), "fail"}, {"comment", strings.Replace(sample, "return v0", "return v0 # v999", 1), "preflight_pass"}, {"string", strings.Replace(sample, "const/16 v0, 10", "const-string v0, \"v999 # hi\"", 1), "preflight_pass"}, {"missing", strings.Replace(sample, ".registers 1", "", 1), "fail"}, {"params", ".method public static x(JD[I)V\n.locals 1\nreturn-void\n.end method", "preflight_pass"}, {"p_overflow", ".method public static x(I)I\n.registers 1\nreturn p1\n.end method", "fail"}, {"multiple", sample + "\n" + sample, "fail"}, {"malformed_literal", strings.Replace(sample, "10", "oops", 1), "fail"}, {"p_physical4", ".method public static x(I)I\n.registers 17\nconst/4 p0, 1\nreturn p0\n.end method", "fail"}, {"param_budget", ".method public x(J)V\n.registers 2\nreturn-void\n.end method", "fail"}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidateSmali(tc.code); got.Status != tc.want {
				t.Fatalf("%+v", got)
			}
		})
	}
}
func TestPatchPlan(t *testing.T) {
	p, e := PlanPatch(sample, PatchRequest{Line: 3, Expected: 10, Replacement: 20, Target: "items"})
	if e != nil {
		t.Fatal(e)
	}
	if p.Delta != 10 || p.Percent == nil || *p.Percent != 100 || p.CanApply || p.Build != "not_run" || p.OriginalHash == p.PatchedHash || !strings.Contains(p.Explanation, "не установлены") {
		t.Fatalf("%+v", p)
	}
	if sample != p.Original {
		t.Fatal("original changed")
	}
	for _, pr := range []PatchRequest{{Line: 0}, {Line: 4, Expected: 10, Replacement: 20}, {Line: 3, Expected: 9, Replacement: 20}, {Line: 3, Expected: 10, Replacement: 10}, {Line: 3, Expected: 10, Replacement: 2147483648}} {
		if _, e := PlanPatch(sample, pr); e == nil {
			t.Fatalf("accepted %+v", pr)
		}
	}
}
func TestOpcodeWidening(t *testing.T) {
	code := strings.Replace(sample, "const/16 v0, 10", "const/4 v0, 7", 1)
	p, e := PlanPatch(code, PatchRequest{Line: 3, Expected: 7, Replacement: 40000})
	if e != nil || !strings.Contains(p.Patched, "const v0, 40000") || p.Validation.Status == "fail" {
		t.Fatalf("%+v %v", p, e)
	}
}
func TestZeroAndNegative(t *testing.T) {
	for _, before := range []int64{0, -10} {
		code := strings.Replace(sample, "10", fmt.Sprint(before), 1)
		p, e := PlanPatch(code, PatchRequest{Line: 3, Expected: before, Replacement: 20})
		if e != nil {
			t.Fatal(e)
		}
		if before == 0 && p.Percent != nil {
			t.Fatal("division by zero")
		}
		if before < 0 && !strings.Contains(p.Explanation, "отрицательному") {
			t.Fatal(p.Explanation)
		}
	}
}
func TestScopeAndConflictBlocks(t *testing.T) {
	for _, scope := range []string{"audit", ""} {
		r := req()
		r.Scope = scope
		r.Patch = &PatchRequest{3, 10, 20, ""}
		out, e := Analyze(r, nil, nil)
		if e != nil || out.Decision != "blocked" || out.Plan != nil {
			t.Fatalf("%+v %v", out, e)
		}
	}
	r := req()
	c := Condition{"x", "eq", true}
	r.State["x"] = true
	r.Questions = []Question{{Text: "conflict", TrueWhen: []Condition{c}, FalseWhen: []Condition{c}}}
	r.Patch = &PatchRequest{3, 10, 20, ""}
	out, _ := Analyze(r, nil, nil)
	if out.Decision != "blocked" || out.Plan != nil {
		t.Fatal(out)
	}
}
func TestNoAutoApply(t *testing.T) {
	r := req()
	r.Threshold = &Thresholds{0, 0}
	r.Patch = &PatchRequest{3, 10, 20, ""}
	out, e := Analyze(r, nil, nil)
	if e != nil || out.Decision != "candidate_for_review" || out.Plan.CanApply {
		t.Fatalf("%+v %v", out, e)
	}
}
func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`{"wat":1}`, `{} {}`, `{"code":"x","threshold":{"finding":true}}`} {
		var r Request
		if Decode([]byte(s), &r) == nil {
			t.Fatal(s)
		}
	}
	var r Request
	if Decode([]byte(`{"code":"x","state":{"n":2}}`), &r) != nil {
		t.Fatal("valid JSON")
	}
	if _, ok := r.State["n"].(json.Number); !ok {
		t.Fatal("numeric typing")
	}
}
func TestFeatureBounds(t *testing.T) {
	r := req()
	r.Code = strings.Replace(sample, "return v0", strings.Repeat("invoke-static {}, Lx;->a()V\n", 1000)+"return v0", 1)
	for k, v := range Features(r) {
		if v < 0 || v > 1 || !finite(v) {
			t.Fatal(k, v)
		}
	}
}
func synthetic() Dataset {
	d := Dataset{Target: "finding"}
	for g := 0; g < 40; g++ {
		for j := 0; j < 8; j++ {
			r := req()
			label := j % 2
			if label == 1 {
				r.Meta.Evidence = []string{"test evidence"}
				r.Meta.AppOwned = true
			} else {
				r.Meta.Library = true
				r.Meta.AppOwned = false
			}
			d.Samples = append(d.Samples, TrainingSample{Group: fmt.Sprintf("synthetic-%d", g), Label: label, Input: r})
		}
	}
	return d
}
func TestTrainingRoundTrip(t *testing.T) {
	m, e := Train(synthetic())
	if e != nil {
		t.Fatal(e)
	}
	if m.Metrics.TrainCount+m.Metrics.CalibrationCount+m.Metrics.TestCount != 320 {
		t.Fatal(m.Metrics)
	}
	b, _ := json.Marshal(m)
	var copy Model
	if e = Decode(b, &copy); e != nil {
		t.Fatal(e)
	}
	r := req()
	a, e := Analyze(r, &copy, nil)
	if e != nil || a.Finding.Kind != "heldout_calibrated_model_estimate" {
		t.Fatalf("%+v %v", a, e)
	}
	copy.Weights[0] = math.NaN()
	if copy.Validate() == nil {
		t.Fatal("invalid model")
	}
}
func TestTrainingGuards(t *testing.T) {
	d := synthetic()
	for i := range d.Samples {
		d.Samples[i].Group = "same"
	}
	if _, e := Train(d); e == nil {
		t.Fatal("group leakage")
	}
	d = synthetic()
	for i := range d.Samples {
		d.Samples[i].Label = 1
	}
	if _, e := Train(d); e == nil {
		t.Fatal("single class")
	}
	d = synthetic()
	d.Target = "bad"
	if _, e := Train(d); e == nil {
		t.Fatal("bad target")
	}
}
func TestImportedConfidenceNotAuthority(t *testing.T) {
	b := []byte(`{"schema_version":"2.0.0","patches":[{"patch_id":"p","original_code":".method public static x()V\n.registers 0\nreturn-void\n.end method","confidence":0.999,"apply_safe":true}]}`)
	rs, e := ImportAnalyzer(b)
	if e != nil || len(rs) != 1 || rs[0].Meta.AppOwned || rs[0].Patch != nil || rs[0].Scope != "audit" {
		t.Fatalf("%+v %v", rs, e)
	}
}
func FuzzSmaliNoPanic(f *testing.F) {
	f.Add(sample)
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, code string) {
		if len(code) > 10000 {
			return
		}
		_ = ValidateSmali(code)
		r := req()
		r.Code = code
		_ = Features(r)
	})
}
func TestJSONScenarioSuite(t *testing.T) {
	r := req()
	suite := TestSuite{Cases: []TestCase{{Name: "ok", Input: r, Expected: Expected{Answers: []string{}, Decision: "low_priority", Validation: "preflight_pass", HasPlan: false}}}}
	out, e := RunSuite(suite, nil, nil)
	if e != nil || out.Passed != 1 || out.Failed != 0 {
		t.Fatal(out, e)
	}
	suite.Cases[0].Expected.Decision = "bad"
	suite.Cases[0].Expected.Validation = "bad"
	suite.Cases[0].Expected.HasPlan = true
	suite.Cases[0].Expected.Answers = []string{"true"}
	out, e = RunSuite(suite, nil, nil)
	if e != nil || out.Failed != 1 || len(out.Cases[0].Errors) != 4 {
		t.Fatal(out, e)
	}
	suite.Cases[0].Input.Code = ""
	out, _ = RunSuite(suite, nil, nil)
	if out.Failed != 1 {
		t.Fatal(out)
	}
	if _, e = RunSuite(TestSuite{}, nil, nil); e == nil {
		t.Fatal("empty suite")
	}
}
func TestCommentsAndParameterPatch(t *testing.T) {
	code := ".method public static x(I)I\n.locals 1\nconst/4 p0, 7 # keep comment\nreturn p0\n.end method"
	p, e := PlanPatch(code, PatchRequest{Line: 3, Expected: 7, Replacement: 20})
	if e != nil || !strings.Contains(p.Patched, "const/16 p0, 20 # keep comment") {
		t.Fatal(p, e)
	}
}
func TestCRLFPreserved(t *testing.T) {
	code := strings.ReplaceAll(sample, "\n", "\r\n")
	p, e := PlanPatch(code, PatchRequest{Line: 3, Expected: 10, Replacement: 20})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(p.Patched, "\r\n") != 4 || p.Original != code || strings.Replace(p.Patched, "20", "10", 1) != code {
		t.Fatal("unrelated line ending changes")
	}
}
func TestFieldNamesAreNotRegisters(t *testing.T) {
	code := strings.Replace(sample, "const/16 v0, 10", "iget v0, v0, Lx;->v999:I", 1)
	if v := ValidateSmali(code); v.Status == "fail" {
		t.Fatal(v)
	}
}
func TestSignedHexLiteral(t *testing.T) {
	code := strings.Replace(sample, "const/16 v0, 10", "const/4 v0, 0xffffffff", 1)
	if v := ValidateSmali(code); v.Status == "fail" {
		t.Fatal(v)
	}
	p, e := PlanPatch(code, PatchRequest{Line: 3, Expected: -1, Replacement: 20})
	if e != nil || p.Before != -1 {
		t.Fatal(p, e)
	}
}
func TestPatchSpecificFeatures(t *testing.T) {
	r := req()
	r.Patch = &PatchRequest{3, 10, 40000, ""}
	f := Features(r)
	if f["patch_requested"] != 1 || f["patch_preflight_ok"] != 1 || f["patch_widened_opcode"] != 1 || f["patch_delta_ratio"] != 1 {
		t.Fatal(f)
	}
	r.Patch.Expected = 9
	if Features(r)["patch_preflight_ok"] != 0 {
		t.Fatal("stale feature")
	}
}
func TestPatchModel(t *testing.T) {
	d := synthetic()
	d.Target = "patch"
	if _, e := Train(d); e == nil {
		t.Fatal("missing concrete patch")
	}
	for i := range d.Samples {
		before := int64(10)
		if d.Samples[i].Label == 0 {
			before = 9
		}
		d.Samples[i].Input.Patch = &PatchRequest{3, before, 20, ""}
	}
	m, e := Train(d)
	if e != nil {
		t.Fatal(e)
	}
	r := req()
	r.Patch = &PatchRequest{3, 10, 20, ""}
	out, e := Analyze(r, nil, m)
	if e != nil || out.PatchAssessment.Kind != "heldout_calibrated_model_estimate" {
		t.Fatal(out, e)
	}
	if _, e = Analyze(r, m, nil); e == nil {
		t.Fatal("cross target misuse")
	}
}
func TestAnswerReasonsNameBranch(t *testing.T) {
	q := Question{Text: "Подтверждён ли локальный тест?", TrueWhen: []Condition{{"tests.passed", "eq", true}, {"local_only", "eq", true}}, FalseWhen: []Condition{{"tests.passed", "eq", false}}}
	a := AnswerQuestion(map[string]any{"tests": map[string]any{"passed": true}, "local_only": true}, q)
	if a.State != "true" {
		t.Fatalf("%+v", a)
	}
	if len(a.Reasons) != 3 {
		t.Fatalf("%+v", a)
	}
	for i, r := range a.Reasons {
		want := "false_when: "
		if i < 2 {
			want = "true_when: "
		}
		if !strings.HasPrefix(r, want) {
			t.Fatalf("reason %d = %q, want prefix %q", i, r, want)
		}
	}
}
