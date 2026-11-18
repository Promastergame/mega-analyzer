package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"decisionai/evalkit"
	"decisionai/gnn"
	"decisionai/semai"
	"decisionai/smalirole"
)

// EvalReport is what `decision-ai eval` writes and the /eval page draws.
type EvalReport struct {
	Version   string           `json:"version"`
	Generated string           `json:"generated"`
	Suites    []evalkit.Report `json:"suites"`
	Cases     []EvalCase       `json:"cases,omitempty"` // per-case results on the human sets
}

type EvalCase struct {
	Set, State, Question, Want, Got string
	Conf                            float64
	OK                              bool
}

// runEval: like a benchmark harness — every model is scored on accuracy AND on whether its
// confidence is honest (ECE, Brier, NLL, reliability bins) AND on how much it can decide alone
// at a given risk (selective accuracy, coverage@95/99, AURC).
func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	corpus := fs.String("corpus", "", "apktool corpus root for the smali-role suite (optional)")
	roleModel := fs.String("role-model", "models/smalirole-model.json", "smali-role LR model (GNN is loaded next to it)")
	human := fs.String("human", "semai/testdata", "folder with events-human*.jsonl")
	out := fs.String("out", "", "write report JSON here (default stdout)")
	synth := fs.Int("synthetic", 1500, "synthetic stories per split")
	compare := fs.String("compare", "", "extra event models to compare, name=path,name=path (e.g. CE vs CE+Brier runs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep := EvalReport{Version: "semai " + semai.Version + " · smalirole " + smalirole.Version, Generated: time.Now().UTC().Format(time.RFC3339)}
	var exp []evalkit.Report // shown after the shipped models
	// 0. experiments: other event-model runs on the same suites (training-verb models only)
	if *compare != "" {
		shipped := semai.EventModel()
		for _, kv := range strings.Split(*compare, ",") {
			name, path, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("-compare wants name=path")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			m, err := gnn.Load(b)
			if err != nil {
				return err
			}
			semai.SetEventModel(m)
			for _, sp := range []struct {
				n    string
				held bool
				seed int64
			}{{"known verbs", false, 3}, {"unseen verbs", true, 4}} {
				ex := semai.GenerateEvents(*synth, sp.seed, sp.held)
				var ev []evalkit.Pred
				for _, g := range semai.EventGraphs(ex) {
					for t, p := range m.Predict(g) {
						ev = append(ev, evalkit.FromProbs(p, g.Labels[t], 0))
					}
				}
				r := evalkit.Compute("experiment "+name+" · "+sp.n+" (per step)", ev, semai.EventClasses)
				r.Note = "trained on 75% of verbs; loss: " + name
				exp = append(exp, r)
			}
		}
		semai.SetEventModel(shipped)
	}
	// 1. events GNN on synthetic stories: per-event decisions + final answers
	allVerbs := false
	if mm, ok := semai.EventModel().Metrics.(map[string]any); ok {
		allVerbs, _ = mm["all_verbs"].(bool)
	}
	for _, sp := range []struct {
		name string
		held bool
		seed int64
	}{{"events · synthetic, known verbs", false, 3}, {"events · synthetic, unseen verbs", true, 4}} {
		ex := semai.GenerateEvents(*synth, sp.seed, sp.held)
		var ev, an []evalkit.Pred
		m := semai.EventModel()
		for i, g := range semai.EventGraphs(ex) {
			for t, p := range m.Predict(g) {
				ev = append(ev, evalkit.FromProbs(p, g.Labels[t], 0))
			}
			an = append(an, answerPred(semai.SolveEvents(ex[i].State, ex[i].Question), ex[i].Answer))
		}
		r := evalkit.Compute(sp.name+" (per step)", ev, semai.EventClasses)
		r.Note = "each story step: plus / minus / none / init"
		if sp.held && allVerbs {
			r.Note = "shipped model saw these verbs too (see experiment runs for true unseen-verb numbers)"
		}
		rep.Suites = append(rep.Suites, r)
		r = evalkit.Compute(sp.name+" (answers)", an, nil)
		r.Note = "final yes/no/number after exact arithmetic over the GNN's step distribution"
		if sp.held && allVerbs {
			r.Note = "shipped model saw these verbs too"
		}
		rep.Suites = append(rep.Suites, r)
	}
	// 2. hand-written stories (dev was used for fixing; test was not looked at while tuning)
	for _, h := range []struct{ file, name, note string }{
		{"events-human.jsonl", "events · human dev", "hand-written; used while fixing the generator"},
		{"events-human-test.jsonl", "events · human test (closed)", "hand-written; not used for tuning"},
	} {
		f, err := os.Open(filepath.Join(*human, h.file))
		if err != nil {
			continue
		}
		var ps []evalkit.Pred
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var c struct{ State, Question, Answer string }
			if json.Unmarshal(sc.Bytes(), &c) != nil || c.State == "" {
				continue
			}
			a := semai.SolveFacts(c.State, c.Question)
			p := answerPred(a, c.Answer)
			ps = append(ps, p)
			got := "—"
			if a != nil {
				got = a.Answer
			}
			rep.Cases = append(rep.Cases, EvalCase{Set: h.name, State: c.State, Question: c.Question, Want: c.Answer, Got: got, Conf: p.Conf, OK: p.Correct})
		}
		f.Close()
		r := evalkit.Compute(h.name, ps, nil)
		r.Note = h.note
		rep.Suites = append(rep.Suites, r)
	}
	// 3. smali literal roles on held-out apps (same split as training)
	if *corpus != "" {
		lr, err := smalirole.LoadModel(*roleModel)
		if err != nil {
			return err
		}
		ex, err := smalirole.GraphDataset(*corpus, 300)
		if err != nil {
			return err
		}
		var pl, pg, pm []evalkit.Pred
		for _, e := range ex {
			if h := sha1.Sum([]byte(e.App)); int(h[0])%10 < 8 {
				continue
			}
			a := smalirole.Softmax(lr.Logits(e.Feats), lr.Temperature)
			pl = append(pl, evalkit.FromProbs(a, e.Label, 0))
			if lr.Graph != nil {
				b := lr.Graph.Predict(e.Graph)[0]
				mix := make([]float64, len(a))
				for i := range a {
					mix[i] = 0.5*a[i] + 0.5*b[i]
				}
				pg = append(pg, evalkit.FromProbs(b, e.Label, 0))
				pm = append(pm, evalkit.FromProbs(mix, e.Label, 0))
			}
		}
		for _, x := range []struct {
			n string
			p []evalkit.Pred
		}{{"smali roles · logistic", pl}, {"smali roles · GNN", pg}, {"smali roles · LR+GNN mix (shipped)", pm}} {
			if len(x.p) > 0 {
				r := evalkit.Compute(x.n, x.p, smalirole.Labels)
				r.Note = "held-out apps, sink call hidden (masked)"
				rep.Suites = append(rep.Suites, r)
			}
		}
	}
	rep.Suites = append(rep.Suites, exp...)
	b, _ := json.MarshalIndent(rep, "", " ")
	if *out == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(*out, b, 0o644)
}

// answerPred: right/wrong at the stated confidence; no answer at all = abstained.
func answerPred(a *semai.FactAnswer, want string) evalkit.Pred {
	if a == nil {
		return evalkit.Pred{Abstained: true}
	}
	conf := a.Confidence
	if a.Answer == "unknown" && conf == 0 {
		conf = 0.5
	}
	return evalkit.Pred{Conf: conf, Correct: a.Answer == want}
}
