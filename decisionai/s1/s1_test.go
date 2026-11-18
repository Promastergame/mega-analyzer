package s1

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"sync"
	"testing"

	"decisionai/semai"
)

// fake backend: entailment = fraction of hypothesis words present in premise.
type fake struct{}

func (fake) Name() string        { return "fake" }
func (fake) Tokens(s string) int { return len(strings.Fields(s)) }
func (fake) JudgeBatch(ps []Pair) []Judgement {
	return LexicalBackend{}.JudgeBatch(ps)
}

func req(t *testing.T, s string) Request {
	t.Helper()
	var r Request
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

const ticket = `{"state":"Shoes arrived two weeks late and in the wrong size. I want a refund.",
 "questions":{
  "dept":{"type":"choice","instructions":"Which team should handle this?","criteria":{"returns":"Exchanges, wrong size or damaged items","shipping":"Delivery status, lost packages","billing":"Charges and invoices","other":null}},
  "human":{"type":"noul","instructions":"Is the customer asking for a human agent?"},
  "refund":{"type":"noul","instructions":"Does the customer want money back?","criteria":{"true":"The customer wants a refund","false":"No refund requested"}},
  "urgency":{"type":"score","instructions":"How urgent?","criteria":{"0":"Not urgent","1":"Somewhat","2":"Very urgent"}}}}`

func TestTypeSafeShape(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	resp, err := e.Decide(req(t, ticket))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answers) != 4 {
		t.Fatalf("answers: %d", len(resp.Answers))
	}
	checkAnswer(t, resp.Answers["dept"], []string{"returns", "shipping", "billing", "other"})
	checkAnswer(t, resp.Answers["urgency"], []string{"0", "1", "2"})
	if a := resp.Answers["refund"]; a.Noul == nil || a.Choice != "" || a.Probabilities != nil {
		t.Fatalf("noul shape %+v", a)
	}
	b, _ := json.Marshal(resp.Answers["dept"])
	if !strings.Contains(string(b), `"probabilities":{"returns":`) {
		t.Fatalf("probabilities must keep declaration order: %s", b)
	}
}

func checkAnswer(t *testing.T, a Answer, keys []string) {
	t.Helper()
	if len(a.Probabilities) != len(keys) {
		t.Fatalf("probabilities %v", a.Probabilities)
	}
	sum := 0.0
	for i, kv := range a.Probabilities {
		if kv.Key != keys[i] || math.IsNaN(kv.P) || kv.P < 0 || kv.P > 1 {
			t.Fatalf("bad prob %v", kv)
		}
		sum += kv.P
	}
	if math.Abs(sum-1) > 1e-6 {
		t.Fatalf("sum %v", sum)
	}
	if a.Confidence == nil || *a.Confidence < 0 || *a.Confidence > 1 {
		t.Fatal("confidence")
	}
	if a.Type == TypeChoice {
		ok := false
		for _, k := range keys {
			ok = ok || k == a.Choice
		}
		if !ok {
			t.Fatalf("choice %q not declared", a.Choice)
		}
	}
	if a.Type == TypeScore && (a.Score == nil || *a.Score < 0 || *a.Score > float64(len(keys)-1)) {
		t.Fatal("score out of range")
	}
}

func TestConfidenceFormulas(t *testing.T) {
	if c := ChoiceConfidence([]float64{.9, .06, .04}); math.Abs(c-.85) > 1e-9 {
		t.Fatal(c)
	}
	if c := ChoiceConfidence([]float64{1. / 3, 1. / 3, 1. / 3}); math.Abs(c) > 1e-9 {
		t.Fatal(c)
	}
	if c := ScoreConfidence([]float64{0, 0, 1, 0, 0}); c != 1 {
		t.Fatal(c)
	}
	if c := ScoreConfidence([]float64{.2, .2, .2, .2, .2}); c > 0.01 {
		t.Fatal(c)
	}
	near := ScoreConfidence([]float64{0, .55, .45, 0, 0})
	far := ScoreConfidence([]float64{.55, 0, 0, 0, .45})
	if !(near > far) {
		t.Fatalf("neighbours must cost less: %v %v", near, far)
	}
}

func TestValidation(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	bad := []string{
		`{"state":"x","questions":{}}`,
		`{"state":"","questions":{"a":{"type":"noul","instructions":"x"}}}`,
		`{"state":"x","questions":{"a":{"type":"text","instructions":"x"}}}`,
		`{"state":"x","questions":{"a":{"type":"choice","instructions":"x","criteria":{"one":"1"}}}}`,
		`{"state":"x","questions":{"a":{"type":"choice","instructions":"x","criteria":{"a":"1","a":"2"}}}}`,
		`{"state":"x","questions":{"a":{"type":"noul","instructions":"x","criteria":{"maybe":"?"}}}}`,
		`{"state":"x","questions":{"a":{"type":"noul","instructions":""}}}`,
	}
	for _, s := range bad {
		if _, err := e.Decide(req(t, s)); err == nil {
			t.Errorf("expected error for %s", s)
		}
	}
}

func TestJSONStateLinearized(t *testing.T) {
	s, err := LinearizeState(json.RawMessage(`{"tests":{"passed":true,"count":3},"note":"ok","x":null}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tests.passed: да / true", "tests.count: 3", "note: ok", "x: null"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %q", want, s)
		}
	}
}

func TestChunkCoversLongState(t *testing.T) {
	long := strings.Repeat("Сборка прошла успешно. ", 40) + "Финальный тест упал."
	cs := Chunk(long, 20, 6)
	if len(cs) > 6 || !strings.Contains(cs[len(cs)-1], "Финальный тест упал") {
		t.Fatalf("tail lost: %d %q", len(cs), cs[len(cs)-1])
	}
}

func TestManyOptionsAndOrderInvariance(t *testing.T) {
	crit := map[string]string{}
	for i := 0; i < 255; i++ {
		crit[string(rune('a'+i%26))+strings.Repeat("x", i/26)] = "option text"
	}
	b, _ := json.Marshal(map[string]any{"state": "hello", "questions": map[string]any{"q": map[string]any{"type": "choice", "instructions": "pick", "criteria": crit}}})
	e := NewEngine(fake{}, DefaultCalibration())
	if _, err := e.Decide(req(t, string(b))); err != nil {
		t.Fatal(err)
	}
	crit["overflow"] = "x"
	b, _ = json.Marshal(map[string]any{"state": "hello", "questions": map[string]any{"q": map[string]any{"type": "choice", "instructions": "pick", "criteria": crit}}})
	if _, err := e.Decide(req(t, string(b))); err == nil {
		t.Fatal("256 options must be rejected")
	}
}

func TestFitTemperatureRecoversOverconfidence(t *testing.T) {
	// logits are 3x too sharp: true temperature ~3
	var ts []target
	for i := 0; i < 400; i++ {
		z := float64(i%20-10) / 2 * 3
		p := sigmoid(z / 3)
		lab := 0.0
		if float64((i*7919)%1000)/1000 < p {
			lab = 1
		}
		ts = append(ts, target{typ: TypeNoul, z: []float64{z}, dist: []float64{lab, 1 - lab}})
	}
	c := FitTemperatures(ts)
	if c.Temps[TypeNoul] < 2 || c.Temps[TypeNoul] > 4.5 {
		t.Fatalf("temperature %v", c.Temps[TypeNoul])
	}
}

func TestEvaluateAndCalibrate(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	data := []Labelled{{Request: req(t, ticket), Labels: map[string]json.RawMessage{
		"dept": json.RawMessage(`"returns"`), "refund": json.RawMessage(`true`), "human": json.RawMessage(`0.1`),
		"urgency": json.RawMessage(`{"1":0.6,"2":0.4}`)}}}
	rep := e.Evaluate(data)
	if len(rep.Errors) > 0 || rep.Questions != 4 || len(rep.ByType) != 3 {
		t.Fatalf("%+v", rep)
	}
	if _, errs := e.Calibrate(data); len(errs) > 0 {
		t.Fatal(errs)
	}
	data[0].Labels["dept"] = json.RawMessage(`"not_an_option"`)
	if rep := e.Evaluate(data); len(rep.Errors) == 0 {
		t.Fatal("undeclared label must be reported")
	}
}

func FuzzDecideTypeSafe(f *testing.F) {
	f.Add("state text", "pick one", "a", "b", "first", "second")
	f.Add(`{"k":1}`, "", "", "x", "", "")
	e := NewEngine(fake{}, DefaultCalibration())
	f.Fuzz(func(t *testing.T, state, instr, k1, k2, d1, d2 string) {
		b, _ := json.Marshal(map[string]any{"state": state, "questions": map[string]any{
			"c": map[string]any{"type": "choice", "instructions": instr, "criteria": map[string]any{k1: d1, k2: d2}},
			"n": map[string]any{"type": "noul", "instructions": instr}}})
		var r Request
		if json.Unmarshal(b, &r) != nil {
			return
		}
		resp, err := e.Decide(r)
		if err != nil {
			return
		}
		c := resp.Answers["c"]
		opts, _ := orderedOptions(r.Questions["c"].Criteria) // keys as the server saw them
		declared := false
		for _, o := range opts {
			declared = declared || o.Key == c.Choice
		}
		if !declared {
			t.Fatalf("undeclared choice %q", c.Choice)
		}
		if n := resp.Answers["n"]; n.Noul == nil || math.IsNaN(*n.Noul) || *n.Noul < 0 || *n.Noul > 1 {
			t.Fatal("noul out of range")
		}
	})
}

// --- real model tests (skipped when weights are absent) ---

var (
	encOnce sync.Once
	encVal  *semai.Encoder
)

func realEncoder(t testing.TB) *semai.Encoder {
	encOnce.Do(func() {
		enc, err := semai.LoadEncoder("../models/encoder-tiny.dte")
		if err != nil {
			return
		}
		if ce, err := semai.LoadCrossEncoder("../models/nli-tiny.dte", enc); err == nil {
			enc.AttachCross(ce)
			encVal = ce
		}
	})
	if encVal == nil {
		t.Skip("NLI weights not available")
	}
	return encVal
}

func TestRealNLIConcurrentAndCached(t *testing.T) {
	if _, err := os.Stat("../models/nli-tiny.dte"); err != nil {
		t.Skip()
	}
	b := NewNLIBackend(realEncoder(t), 4)
	e := NewEngine(b, DefaultCalibration())
	r := req(t, ticket)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := e.Decide(r)
			if err != nil {
				t.Error(err)
				return
			}
			checkAnswer(t, resp.Answers["dept"], []string{"returns", "shipping", "billing", "other"})
		}()
	}
	wg.Wait()
	resp, _ := e.Decide(r)
	if resp.Usage.CacheHits == 0 || resp.Usage.ModelCalls != 0 {
		t.Fatalf("second identical call must be fully cached: %+v", resp.Usage)
	}
}
