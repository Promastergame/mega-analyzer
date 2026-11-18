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

func TestPlansMirrorEngine(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	chunks, plans, err := e.Plans(req(t, `{"state":"Тест прошёл на текущей сборке.","questions":{
		"ok":{"type":"noul","instructions":"Подтверждён ли эффект?","criteria":{"true":"Эффект виден","false":"Эффекта нет"}},
		"bare":{"type":"noul","instructions":"Тест прошёл?"},
		"role":{"type":"choice","instructions":"Роль литерала","criteria":{"limit":"Лимит значения","other":null}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || len(plans) != 3 {
		t.Fatalf("chunks %d plans %d", len(chunks), len(plans))
	}
	by := map[string]QuestionPlan{}
	for _, p := range plans {
		by[p.ID] = p
	}
	if o := by["ok"].Options; o[0].Hyp != "Эффект виден" || o[1].Hyp != "Эффекта нет" {
		t.Fatalf("noul criteria hypotheses: %+v", o)
	}
	if o := by["bare"].Options; o[0].Hyp != "Тест прошёл" || !o[1].Escape {
		t.Fatalf("bare noul plan: %+v", o)
	}
	if o := by["role"].Options; o[0].Hyp != "Роль литерала: Лимит значения" || !o[1].Escape {
		t.Fatalf("choice plan: %+v", o)
	}
}

func TestScoreArrayCriteriaJevStyle(t *testing.T) {
	e := NewEngine(fake{}, DefaultCalibration())
	resp, err := e.Decide(req(t, `{"model":"typesafe/jev-1.13","state":"Help! My payouts have been failing for 3 days.",
		"questions":{"frustration":{"type":"score","instructions":"How frustrated is the customer?","criteria":["Calm","Frustrated","Very angry"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["frustration"]
	if a.Score == nil || len(a.Probabilities) != 3 || a.Probabilities[2].Key != "2" || a.Legend["1"] != "Frustrated" {
		t.Fatalf("score from array criteria: %+v", a)
	}
}

type countingBackend struct {
	name string
	mu   sync.Mutex
	hyps map[string]bool
}

func (b *countingBackend) Name() string        { return b.name }
func (b *countingBackend) Tokens(s string) int { return len(strings.Fields(s)) }
func (b *countingBackend) JudgeBatch(ps []Pair) []Judgement {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range ps {
		b.hyps[p.Hypothesis] = true
	}
	return LexicalBackend{}.JudgeBatch(ps)
}

func TestSkillBackendScoresOnlySkillQuestions(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []struct{ name, desc string }{{"pdf", "Read, merge and split PDF files"}, {"xlsx", "Spreadsheets, Excel formulas and charts"}} {
		os.MkdirAll(dir+"/"+s.name, 0o755)
		os.WriteFile(dir+"/"+s.name+"/SKILL.md", []byte("---\nname: "+s.name+"\ndescription: "+s.desc+"\n---\n"), 0o644)
	}
	reg, err := LoadSkillRegistry([]string{dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	gen, sk := &countingBackend{name: "general", hyps: map[string]bool{}}, &countingBackend{name: "skills", hyps: map[string]bool{}}
	e := NewEngine(gen, DefaultCalibration())
	e.Skills, e.SkillBackend = reg, sk
	resp, err := e.Decide(req(t, `{"state":"merge two PDF files","questions":{
		"skill":{"type":"choice","task":"skill_routing","instructions":"Какой скил нужен?"},
		"urgent":{"type":"noul","instructions":"The request is urgent"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if gen.hyps["The request is urgent"] != true || sk.hyps["The request is urgent"] {
		t.Fatalf("noul hypothesis went to the wrong backend: general=%v skills=%v", gen.hyps, sk.hyps)
	}
	for h := range gen.hyps {
		if strings.Contains(h, "PDF") {
			t.Fatalf("skill hypothesis scored by the general backend: %q", h)
		}
	}
	if resp.Answers["skill"].Source != "skills" || resp.Answers["urgent"].Source != "general" {
		t.Fatalf("sources: %q %q", resp.Answers["skill"].Source, resp.Answers["urgent"].Source)
	}
	if !strings.Contains(resp.Backend, "skills:skills") {
		t.Fatalf("backend label %q", resp.Backend)
	}
}

// TestDistilledParity checks Go inference of models/s1-distilled.dte against torch
// references (scripts/distill/parity.py) and the decision-blind quality floor.
func TestDistilledParity(t *testing.T) {
	if testing.Short() {
		t.Skip("loads model weights")
	}
	base, err := semai.LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Skip("encoder weights not present")
	}
	d, err := semai.LoadCrossEncoderAny("../models/s1-distilled.dte", base)
	if err != nil {
		t.Skip("distilled weights not present")
	}
	raw, err := os.ReadFile("testdata/distill-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Premise, Hypothesis string
		Sim                 float64
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		p, h := d.Encode(r.Premise), d.Encode(r.Hypothesis)
		got := 0.5*semai.Cosine(p.Mean, h.Mean) + 0.5*semai.MaxSim(h, p)
		if math.Abs(got-r.Sim) > 2e-3 {
			t.Errorf("sim(%q, %q) = %.4f, torch %.4f", r.Premise[:20], r.Hypothesis, got, r.Sim)
		}
	}
	cal, err := LoadCalibration("../models/s1-distilled-calibration.json")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(NewEmbedBackend(d), cal)
	e.LexScale = map[string]float64{TypeNoul: 0, TypeChoice: 1, TypeScore: 0.5}
	f, err := os.Open("../evals/distill/decision-blind.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var data []Labelled
	dec := json.NewDecoder(f)
	for dec.More() {
		var l Labelled
		if err := dec.Decode(&l); err != nil {
			t.Fatal(err)
		}
		data = append(data, l)
	}
	rep := e.Evaluate(data)
	if c, n := rep.ByType[TypeChoice].Agreement, rep.ByType[TypeNoul].Agreement; c < 0.9 || n < 0.8 {
		t.Fatalf("decision-blind: choice %.3f noul %.3f", c, n)
	}
}
