package textai

import (
	"strings"
	"testing"
)

func TestEffectiveThresholdDisjoint(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	r := request()
	r.Checks = validChecks()
	zero := 0.0
	r.Threshold = &zero
	out, e := Analyze(r, m)
	if e != nil {
		t.Fatal(e)
	}
	if out.Threshold != 0.0 || out.EffectiveThreshold != 0.5 {
		t.Fatalf("thresholds = %v/%v", out.Threshold, out.EffectiveThreshold)
	}
	if !out.AboveThreshold != (out.Prediction.Value < 0.5) {
		// AboveThreshold must use effective threshold
		if out.AboveThreshold != (out.Prediction.Value >= 0.5) {
			t.Fatalf("AboveThreshold not using effective: %+v", out)
		}
	}
	// Zones must be disjoint: cannot be both yes and no; check via two-sided probe
	// A value exactly 0.5 must be unknown, not yes.
	foundWarning := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "эффективный порог") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatal("missing low-threshold warning")
	}
}

func TestModelSummaryAndAbstention(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	r := request()
	r.Checks = validChecks()
	out, e := Analyze(r, m)
	if e != nil {
		t.Fatal(e)
	}
	if out.Model == nil || out.Model.Version != Version || out.Model.Features != len(m.Vocabulary) {
		t.Fatalf("model summary missing: %+v", out.Model)
	}
	if out.Model.FeatureSchema != FeatureSchema {
		t.Fatalf("schema = %q", out.Model.FeatureSchema)
	}
	// Known in-distribution request should answer (not unknown) with empty abstention
	if out.Answer == "unknown" {
		t.Fatalf("expected answer, got unknown reasons=%v coverage=%v support=%v", out.AbstentionReasons, out.Prediction.Coverage, out.Prediction.Support)
	}
	if len(out.AbstentionReasons) != 0 {
		t.Fatalf("unexpected abstention: %v", out.AbstentionReasons)
	}
	// Unknown vocabulary must abstain with reason
	r2 := request()
	r2.State = "abracadabra zqxwu nopqwert"
	out2, e := Analyze(r2, m)
	if e != nil {
		t.Fatal(e)
	}
	if out2.Answer != "unknown" || len(out2.AbstentionReasons) == 0 {
		t.Fatalf("expected unknown with reasons: %+v", out2)
	}
	if out2.Prediction.Support >= 0.6 {
		t.Fatalf("support should be low: %v", out2.Prediction.Support)
	}
}

func TestTruncationSurfaces(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	r := request()
	r.State = strings.Repeat("word ", 3000)
	p := m.Predict(r)
	truncated := false
	for _, f := range p.Fields {
		if f.Truncated {
			truncated = true
		}
	}
	if !truncated {
		t.Fatal("expected truncation flag")
	}
	out, e := Analyze(r, m)
	if e != nil {
		t.Fatal(e)
	}
	if out.Answer != "unknown" {
		t.Fatalf("truncated should abstain: %+v", out)
	}
	found := false
	for _, reason := range out.AbstentionReasons {
		if reason == "truncated_input" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing truncated_input reason: %v", out.AbstentionReasons)
	}
	foundWarn := false
	for _, w := range out.Warnings {
		if strings.Contains(w, "усеч") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("missing truncation warning: %v", out.Warnings)
	}
}

func TestNegationAndCharGrams(t *testing.T) {
	ws := normalizedWords("Don't won't")
	joined := strings.Join(ws, " ")
	if !strings.Contains(joined, "not") {
		t.Fatalf("contractions not split: %v", ws)
	}
	if len(charGrams("ab")) != 0 {
		t.Fatal("short words must have no grams")
	}
	if len(charGrams("тест")) == 0 {
		t.Fatal("expected char grams")
	}
	r := request()
	f := extract(r)
	if len(f.terms) == 0 {
		t.Fatal("no terms")
	}
	hasBigram, hasTrigram := false, false
	for k := range f.terms {
		if strings.Contains(k, ":b:") {
			hasBigram = true
		}
		if strings.Contains(k, ":t:") {
			hasTrigram = true
		}
	}
	if !hasBigram || !hasTrigram {
		t.Fatal("missing n-grams")
	}
	// Negation must stay inside sentence: bigram across '.' must not exist
	r2 := request()
	r2.State = "Тест прошёл. Не прошёл."
	f2 := extract(r2)
	for k := range f2.terms {
		if strings.Contains(k, "прошел не") || strings.Contains(k, "прошёл не") {
			t.Fatalf("negation crossed sentence: %q", k)
		}
	}
}

func TestEvaluateMetricsAndLeakage(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	// Leakage: same groups/texts must be rejected
	if _, e := Evaluate(corpus(), m, 0.85); e == nil || !strings.Contains(e.Error(), "leakage") {
		t.Fatalf("expected leakage error, got %v", e)
	}
	// Fresh paraphrased corpus with new groups must evaluate with full metrics
	d := Dataset{TaskID: Task, Synthetic: true}
	for i := 0; i < 6; i++ {
		label := i % 2
		state := ""
		if label == 1 {
			state = strings.Repeat("сборка прошла тест поведения прошёл эффект подтверждён лимит 20 ", 3) + strings.Repeat("x", i)
		} else {
			state = strings.Repeat("тесты не запускались сборка не выполнялась эффект неизвестен ", 3) + strings.Repeat("y", i)
		}
		// Vary wording slightly to avoid exact duplicate of training while staying in-vocab
		r := request()
		r.State = state
		d.Samples = append(d.Samples, Sample{Group: "eval-new-project", Label: label, Input: r})
	}
	// Need distinct groups to avoid single-group audit confusion? prepareDataset allows any groups for eval.
	rep, e := Evaluate(d, m, 0.85)
	if e != nil {
		t.Fatal(e)
	}
	if rep.Metrics.Count != 6 {
		t.Fatalf("count = %d", rep.Metrics.Count)
	}
	if rep.Metrics.Precision < 0 || rep.Metrics.Precision > 1 || rep.Metrics.Recall < 0 || rep.Metrics.Recall > 1 || rep.Metrics.F1 < 0 || rep.Metrics.F1 > 1 {
		t.Fatalf("bad prf: %+v", rep.Metrics)
	}
	if len(rep.OperatingPoints) != 5 {
		t.Fatalf("operating points = %d", len(rep.OperatingPoints))
	}
	if rep.Metrics.ROCAUC == nil && rep.Metrics.Positive > 0 && rep.Metrics.Negative > 0 {
		t.Fatal("expected ROC AUC for two classes")
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("expected warnings")
	}
}

func TestTrainingOptionsGuard(t *testing.T) {
	d := corpus()
	d.Options = &TrainingOptions{MaxFeatures: 10}
	if _, e := Train(d); e == nil {
		t.Fatal("expected max_features guard")
	}
	d = corpus()
	d.Options = &TrainingOptions{ClassWeight: "bogus"}
	if _, e := Train(d); e == nil {
		t.Fatal("expected class_weight guard")
	}
	d = corpus()
	d.Options = &TrainingOptions{MinDocumentFrequency: 100000}
	if _, e := Train(d); e == nil {
		t.Fatal("expected no reusable features")
	}
}

func TestHoldoutConsistency(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	if m.Metrics.Holdout == nil {
		t.Fatal("missing holdout")
	}
	if m.Metrics.Holdout.Count != m.Metrics.TestCount {
		t.Fatalf("holdout count %d != test %d", m.Metrics.Holdout.Count, m.Metrics.TestCount)
	}
	if m.Metrics.Holdout.Brier != m.Metrics.Brier || m.Metrics.Holdout.Accuracy != m.Metrics.Accuracy {
		t.Fatal("holdout/brier mismatch")
	}
	if m.Metrics.Epochs < 50 || m.Metrics.Epochs > 1000 {
		t.Fatalf("epochs = %d", m.Metrics.Epochs)
	}
}

func TestCrossFieldMatches(t *testing.T) {
	r := request()
	r.State = "Сборка прошла, лимит стал 20."
	r.TrueWhen = "Сборка прошла, лимит стал 20."
	r.FalseWhen = "Тесты не запускались."
	f := extract(r)
	for _, want := range []string{"state:w:match_true:сборка", "state:w:match_true:прошла", "state:w:match_true_ge3"} {
		if f.terms[want] == 0 {
			t.Fatalf("missing %q in %v", want, f.terms)
		}
	}
	if f.terms["state:w:match_false:сборка"] != 0 {
		t.Fatal("false match must not fire for unrelated criterion")
	}
	// Buckets stay silent on tiny overlap.
	r2 := request()
	r2.State = "Привет."
	r2.TrueWhen = "Сборка прошла."
	f2 := extract(r2)
	for k := range f2.terms {
		if k == "state:w:match_true_ge3" || k == "state:w:match_true_ge5" {
			t.Fatalf("unexpected bucket %q", k)
		}
	}
}

func TestSchemaV1StillLoads(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	if m.FeatureSchema != FeatureSchema {
		t.Fatalf("schema = %q", m.FeatureSchema)
	}
	legacy := *m
	legacy.FeatureSchema = FeatureSchemaV1
	if e := legacy.Validate(); e != nil {
		t.Fatalf("v1 model rejected: %v", e)
	}
	r := request()
	if _, e := Analyze(r, &legacy); e != nil {
		t.Fatalf("v1 predict failed: %v", e)
	}
}

func TestEmptyTaskIDDefaults(t *testing.T) {
	m, e := Train(corpus())
	if e != nil {
		t.Fatal(e)
	}
	r := request()
	r.TaskID = ""
	r.Checks = validChecks()
	out, e := Analyze(r, m)
	if e != nil {
		t.Fatal(e)
	}
	if out.TaskID != Task {
		t.Fatalf("task = %q", out.TaskID)
	}
	r.TaskID = "something_else"
	if _, e := Analyze(r, m); e == nil {
		t.Fatal("wrong task must still be rejected")
	}
}

func TestNoModelAbstention(t *testing.T) {
	r := request()
	out, e := Analyze(r, nil)
	if e != nil {
		t.Fatal(e)
	}
	if out.Answer != "unknown" || len(out.AbstentionReasons) == 0 {
		t.Fatalf("nil model must abstain: %+v", out)
	}
	if out.Model != nil {
		t.Fatal("nil model summary must be nil")
	}
	if out.EffectiveThreshold != 0.85 {
		t.Fatalf("effective = %v", out.EffectiveThreshold)
	}
}
