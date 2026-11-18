package semai

import (
	"math"
	"os"
	"testing"
)

func loadModels(t *testing.T) *Encoder {
	t.Helper()
	if _, err := os.Stat("../models/encoder-tiny.dte"); err != nil {
		t.Skip("encoder weights not present")
	}
	e, err := LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("../models/nli-tiny.dte"); err == nil {
		c, err := LoadCrossEncoder("../models/nli-tiny.dte", e)
		if err != nil {
			t.Fatal(err)
		}
		e.AttachCross(c)
	}
	return e
}

func ask(t *testing.T, q string, enc *Encoder) Report {
	t.Helper()
	r, err := Analyze(Request{Question: q}, enc)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFindNumbers(t *testing.T) {
	cases := map[string]float64{"3,5 мыши": 3.5, "3.5 mice": 3.5, "три с половиной мыши": 3.5, "полторы кошки": 1.5, "двадцать пять собак": 25, "two and a half cats": 2.5, "1/2 яблока": 0.5, "3 1/2 мыши": 3.5, "семь": 7}
	for in, want := range cases {
		ns := FindNumbers(tokens(in))
		if len(ns) != 1 || math.Abs(ns[0].Val-want) > 1e-9 {
			t.Errorf("%q -> %+v want %v", in, ns, want)
		}
	}
}

func TestParseChoices(t *testing.T) {
	stem, o := ParseChoices("Сколько ушей у 3,5 мыши?\nA)7\nB)6\nC)8", nil)
	if stem != "Сколько ушей у 3,5 мыши?" || len(o) != 3 || o[0].Text != "7" || *o[2].Value != 8 {
		t.Fatalf("%q %+v", stem, o)
	}
	_, o = ParseChoices("Сколько? А) 7 Б) 6 В) 8", nil)
	if len(o) != 3 || o[1].Text != "6" {
		t.Fatalf("cyrillic %+v", o)
	}
	_, o = ParseChoices("Что больше? 1) 3.5 2) 4", nil)
	if len(o) != 2 || *o[0].Value != 3.5 {
		t.Fatalf("digits %+v", o)
	}
	_, o = ParseChoices("Просто число 3.5 без вариантов", nil)
	if len(o) != 0 {
		t.Fatalf("false positive %+v", o)
	}
	_, o = ParseChoices("q", []string{"x", "невозможно определить"})
	if len(o) != 2 || !o[1].IsUnknown {
		t.Fatalf("explicit %+v", o)
	}
}

// The motivating example: half a mouse can be cut vertically (7 ears), across keeping the head (8) or without it (6).
func TestHalfMouseIsUnknown(t *testing.T) {
	r := ask(t, "Сколько ушей у 3,5 мыши?\nA) 7\nB) 6\nC) 8", nil)
	if r.Answer != "unknown" || r.Verdict != "unknown" {
		t.Fatalf("want unknown, got %+v", r.Answer)
	}
	p := map[string]float64{}
	for _, c := range r.Candidates {
		p[c.Label] = c.Prob
	}
	if p["A"] <= 0 || p["B"] <= 0 || p["C"] <= 0 || p["A"] > 0.5 {
		t.Fatalf("every option must be plausible under some reading: %v", p)
	}
	if len(r.Readings) != 5 {
		t.Fatalf("readings: %d", len(r.Readings))
	}
	// English, and an explicit "cannot be determined" option becomes the answer
	r = ask(t, "How many ears do 3.5 mice have?\nA) 7\nB) 6\nC) 8\nD) cannot be determined", nil)
	if r.Answer != "D" {
		t.Fatalf("got %s", r.Answer)
	}
}

func TestMissingSubject(t *testing.T) {
	r := ask(t, "сколько ушей у 3,5\nA)7\nB)6\nC)8", nil)
	if r.Answer != "unknown" || len(r.Abstention) == 0 || r.Abstention[0] != "missing_subject" {
		t.Fatalf("%+v", r)
	}
}

func TestWholeAnimalsAreCertain(t *testing.T) {
	r := ask(t, "Сколько ушей у 3 мышей?\nA) 7\nB) 6\nC) 8", nil)
	if r.Answer != "B" || r.Confidence < 0.9 {
		t.Fatalf("%s %.2f", r.Answer, r.Confidence)
	}
	r = ask(t, "Сколько ног у трёх пауков?", nil)
	if r.Answer != "24" {
		t.Fatalf("spider legs: %s", r.Answer)
	}
	r = ask(t, "How many eyes do 2 cats and 1 dog have?", nil)
	if r.Answer != "6" {
		t.Fatalf("eyes: %s", r.Answer)
	}
	r = ask(t, "Сколько рогов у 2 котов?", nil)
	if r.Verdict != "unknown" || r.Abstention[0] != "no_knowledge" {
		t.Fatalf("cats have no horn data: %+v", r.Abstention)
	}
}

func TestOptionNotAmongReadings(t *testing.T) {
	r := ask(t, "Сколько ушей у 2 мышей?\nA) 3\nB) 5\nC) 9", nil)
	if r.Verdict != "unknown" || r.Abstention[0] != "no_option_matches" {
		t.Fatalf("%+v", r)
	}
}

func TestArithmetic(t *testing.T) {
	r := ask(t, "Сколько будет 2+2*2?\nA) 8\nB) 6\nC) 4", nil)
	if r.Answer != "B" {
		t.Fatalf("%s", r.Answer)
	}
	r = ask(t, "чему равно (3,5 + 1,5) * 2", nil)
	if r.Answer != "10" {
		t.Fatalf("%s", r.Answer)
	}
	// the viral ambiguous expression
	r = ask(t, "Сколько будет 6/2(1+2)?", nil)
	if r.Verdict != "unknown" || len(r.PossibleSet) != 2 {
		t.Fatalf("%+v", r)
	}
	r = ask(t, "6÷2(1+2)=?\nA) 1\nB) 9", nil)
	if r.Verdict != "unknown" {
		t.Fatalf("%+v", r)
	}
	r = ask(t, "Сколько будет 1/0?", nil)
	if r.Verdict != "unknown" {
		t.Fatalf("division by zero should abstain: %+v", r)
	}
}

func TestUnknownTopicAbstains(t *testing.T) {
	r := ask(t, "Какая столица Франции?\nA) Париж\nB) Лион", nil)
	if r.Verdict != "unknown" || r.Abstention[0] != "no_semantic_frame" {
		t.Fatalf("%+v", r)
	}
}

func TestThresholdValidation(t *testing.T) {
	bad := 0.2
	if _, err := Analyze(Request{Question: "x", Threshold: &bad}, nil); err == nil {
		t.Fatal("threshold < 0.5 must be rejected")
	}
	if _, err := Analyze(Request{}, nil); err == nil {
		t.Fatal("empty request must be rejected")
	}
	if _, err := Analyze(Request{Question: "Сколько ушей у 3,5 мыши?\nA) 7\nB) 6\nC) 8", Options: make([]string, 13)}, nil); err == nil {
		t.Fatal("too many options")
	}
}

func TestPolarityParity(t *testing.T) {
	for s, want := range map[string]int{"Тест прошёл": 1, "Тест не прошёл": -1, "Нет ошибок": 1, "Сборка завершилась ошибкой": -1, "The build did not fail": 1, "tests failed": -1, "без ошибок": 1} {
		if got := polarity(s); got != want {
			t.Errorf("%q: got %d want %d", s, got, want)
		}
	}
}

func TestEncoderMatchesPyTorchReference(t *testing.T) {
	e := loadModels(t)
	ref := []struct {
		text string
		ids  []int
		cls  [3]float64
	}{
		{"Привет, мир!", []int{2, 51343, 16, 9311, 5, 3}, [3]float64{0.00055, 0.00768, -0.00743}},
		{"Тест прошёл успешно, эффект подтверждён.", []int{2, 56183, 19051, 13547, 16, 29618, 62218, 18, 3}, [3]float64{-0.06953, -0.02529, -0.01131}},
		{"The build failed with an error (code 42).", []int{2, 543, 7110, 6081, 594, 576, 10920, 12, 4354, 1361, 13, 18}, [3]float64{-0.13396, -0.07313, 0.04362}},
		{"Сколько ушей у 3,5 мыши?", []int{2, 33420, 55044, 331, 23, 16, 25, 46258, 35, 3}, [3]float64{-0.00850, 0.02183, -0.01833}},
	}
	for _, r := range ref {
		ids := e.Tokenize(r.text, 128)
		if len(ids) < len(r.ids) {
			t.Fatalf("%q: ids %v", r.text, ids)
		}
		for i, id := range r.ids {
			if ids[i] != id {
				t.Fatalf("%q: token %d = %d, want %d", r.text, i, ids[i], id)
			}
		}
		en := e.Encode(r.text)
		for i := 0; i < 3; i++ {
			if math.Abs(float64(en.CLS[i])-r.cls[i]) > 0.006 { // int8 word-table quantisation noise
				t.Errorf("%q: cls[%d]=%.5f want %.5f", r.text, i, en.CLS[i], r.cls[i])
			}
		}
	}
}

func TestSemanticSimilarityOrdering(t *testing.T) {
	e := loadModels(t)
	a := e.Encode("Тест прошёл успешно")
	near := e.Encode("Проверка завершилась удачно")
	far := e.Encode("Кошка спит на диване")
	if Cosine(a.CLS, near.CLS) <= Cosine(a.CLS, far.CLS) {
		t.Fatal("paraphrase must be closer than unrelated text")
	}
}

func yn(t *testing.T, enc *Encoder, state string) Report {
	t.Helper()
	r, err := Analyze(Request{Question: "Эффект получен?", State: state, TrueWhen: "Тест прошёл и эффект подтверждён", FalseWhen: "Тест не прошёл или сборка завершилась ошибкой"}, enc)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCriteriaWithoutEncoderIsConservative(t *testing.T) {
	r := yn(t, nil, "Сегодня хорошая погода, мы пошли гулять в парк.")
	if r.Answer != "unknown" {
		t.Fatalf("unrelated state must be unknown, got %s", r.Answer)
	}
	if len(r.Warnings) == 0 {
		t.Fatal("missing-encoder warning expected")
	}
	r = yn(t, nil, "Тест прошёл. Эффект подтверждён.")
	if r.Answer != "yes" {
		t.Fatalf("lexically identical evidence should be yes, got %s (%.2f)", r.Answer, r.Confidence)
	}
}

func TestCriteriaNeural(t *testing.T) {
	e := loadModels(t)
	if !crossOf(e).HasNLI() {
		t.Skip("NLI weights not present")
	}
	cases := []struct{ state, want string }{
		{"Сборка прошла успешно. Тест поведения прошёл. Эффект подтверждён на реальном устройстве.", "yes"},
		{"Сборка собралась, но тест завершился с ошибкой. Эффект не обнаружен.", "no"},
		{"Сегодня хорошая погода, мы пошли гулять в парк.", "unknown"},
		{"Тесты не запускались.", "unknown"},
	}
	for _, c := range cases {
		if r := yn(t, e, c.state); r.Answer != c.want {
			t.Errorf("%q: got %s (y=%.2f n=%.2f u=%.2f), want %s", c.state, r.Answer, r.Candidates[0].Prob, r.Candidates[1].Prob, r.Candidates[2].Prob, c.want)
		}
	}
}

func TestNLIMatchesPyTorchReference(t *testing.T) {
	e := loadModels(t)
	c := crossOf(e)
	if c == nil {
		t.Skip("NLI weights not present")
	}
	ref := []struct {
		a, b string
		p    [3]float64
	}{
		{"Тест прошёл успешно.", "Тест не прошёл.", [3]float64{0.0002, 0.0000, 0.9997}},
		{"Сборка завершилась без ошибок.", "Сборка прошла успешно.", [3]float64{0.9985, 0.0002, 0.0013}},
		{"Тесты не запускались.", "Тест прошёл.", [3]float64{0.0001, 0.9944, 0.0055}},
		{"The tests are green and the app launches normally.", "Приложение запускается.", [3]float64{0.9989, 0.0003, 0.0008}},
		{"Кошка спит на диване.", "Тест прошёл.", [3]float64{0.0001, 0.9986, 0.0013}},
	}
	for _, r := range ref {
		n := c.Classify(r.a, r.b)
		got := [3]float64{n.Entailment, n.Neutral, n.Contradiction}
		for i := range got {
			if math.Abs(got[i]-r.p[i]) > 0.05 {
				t.Errorf("%q => %q: got %.3f want %.3f (class %d)", r.a, r.b, got[i], r.p[i], i)
			}
		}
	}
}

// Fast float32 approximations (ported from nim/dainim.nim) must stay close to
// the stdlib references: NimParity tolerates 1e-4 on the mean vector.
func TestFastMathBounds(t *testing.T) {
	worstExp := 0.0
	for x := -10.0; x <= 10.0; x += 0.01 {
		got := float64(fastExp32(float32(x)))
		want := math.Exp(x)
		rel := math.Abs(got-want) / want
		if rel > worstExp {
			worstExp = rel
		}
	}
	if worstExp > 1e-5 {
		t.Fatalf("fastExp32 worst rel err %g", worstExp)
	}
	if got := fastExp32(-100); got != 0 {
		t.Fatalf("fastExp32(-100) = %g, want 0", got)
	}
	worstGelu := float32(0)
	for x := -6.0; x <= 6.0; x += 0.01 {
		got := geluFast(float32(x))
		want := gelu(float32(x))
		if d := got - want; d < 0 && -d > worstGelu || d >= 0 && d > worstGelu {
			if d < 0 {
				worstGelu = -d
			} else {
				worstGelu = d
			}
		}
	}
	if worstGelu > 1e-5 {
		t.Fatalf("geluFast worst abs err %g", worstGelu)
	}
}

func FuzzAskNoPanic(f *testing.F) {
	for _, s := range []string{"", "Сколько ушей у 3,5 мыши?\nA)7\nB)6", "6/2(1+2)", "((((", "1/0", "A) B) C) D)", "999999999999999999999 мышей ушей", "3 1/ мыши", "(((1+2)", "сколько ног у ½ паука"} {
		f.Add(s, "state text. Another one", "a и b или c")
	}
	f.Fuzz(func(t *testing.T, q, state, crit string) {
		if len(q) > 2000 || len(state) > 2000 || len(crit) > 2000 {
			return
		}
		_, _ = Analyze(Request{Question: q}, nil)
		_, _ = Analyze(Request{Question: q, State: state, TrueWhen: crit, FalseWhen: crit}, nil)
	})
}

func FuzzParseEncoderNoPanic(f *testing.F) {
	f.Add([]byte("DTE1"))
	f.Add([]byte("DTE1\x02\x00\x00\x00{}"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseEncoder(b) })
}
