// events-train trains the event GNN bundled in semai/eventgnn.json on synthetic stories and
// reports held-out accuracy on (a) unseen stories with training verbs, (b) unseen verbs.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"decisionai/gnn"
	"decisionai/semai"
)

func main() {
	n := flag.Int("n", 12000, "training stories")
	epochs := flag.Int("epochs", 12, "epochs")
	hidden := flag.Int("hidden", 32, "hidden size")
	allVerbs := flag.Bool("allverbs", false, "train on all verbs (shipping model; the unseen-verb split is then not a held-out test)")
	seed := flag.Int64("seed", 1, "random seed")
	brier := flag.Float64("brier", 0, "weight of the Brier term (calibration-aware loss)")
	out := flag.String("out", "semai/eventgnn.json", "model output")
	show := flag.Int("show", 0, "print N generated stories and exit")
	errs := flag.String("errors", "", "load this model and print misclassified held-out events")
	flag.Parse()
	if *errs != "" {
		b, err := os.ReadFile(*errs)
		if err != nil {
			panic(err)
		}
		m, err := gnn.Load(b)
		if err != nil {
			panic(err)
		}
		shown := 0
		for _, held := range []bool{false, true} {
			ex := semai.GenerateEvents(1500, 5, held)
			for i, g := range semai.EventGraphs(ex) {
				for t, p := range m.Predict(g) {
					b := 0
					for j := range p {
						if p[j] > p[b] {
							b = j
						}
					}
					if b != g.Labels[t] && shown < 40 {
						shown++
						fmt.Printf("[held=%v] event %d: want %s got %s %.2f\n  %s\n  Q: %s\n", held, t, semai.EventClasses[g.Labels[t]], semai.EventClasses[b], p[b], ex[i].State, ex[i].Question)
					}
				}
			}
		}
		return
	}
	if *show > 0 {
		for _, e := range semai.GenerateEvents(*show, 99, false) {
			fmt.Printf("%s\n  Q: %s -> %s %v\n", e.State, e.Question, e.Answer, e.Labels)
		}
		return
	}
	trainEx := semai.GenerateEvents(*n, *seed, false)
	if *allVerbs {
		trainEx = append(trainEx[:*n*3/4], semai.GenerateEvents(*n/4, *seed+100, true)...)
	}
	train := semai.EventGraphs(trainEx)
	val := semai.EventGraphs(semai.GenerateEvents(1500, 2, false))
	testIn := semai.GenerateEvents(2000, 3, false)
	testOut := semai.GenerateEvents(2000, 4, true)
	m := gnn.New(semai.EventClasses, 4096, *hidden, semai.EventRelations, 3, 6+*seed)
	t0 := time.Now()
	m.Vocab = semai.EventVocab(train)
	m.Train(train, gnn.TrainOptions{Epochs: *epochs, LR: 0.003, Batch: 16, L2: 1e-6, Seed: *seed, Brier: *brier, Verbose: func(ep int, loss float64) {
		acc, _, _ := m.Eval(val)
		fmt.Fprintf(os.Stderr, "epoch %d loss %.4f val-acc %.4f (%s)\n", ep+1, loss/float64(len(train)), acc, time.Since(t0).Round(time.Second))
	}})
	T := m.FitTemperature(val)
	res := map[string]any{"train_stories": *n, "temperature": T, "brier_weight": *brier, "all_verbs": *allVerbs, "seed": *seed}
	for name, ex := range map[string][]semai.EventExample{"test_seen_verbs": testIn, "test_unseen_verbs": testOut} {
		acc, ece, cnt := m.Eval(semai.EventGraphs(ex))
		res[name] = map[string]any{"event_acc": round(acc), "event_ece": round(ece), "events": cnt, "answer_acc": round(answerAcc(m, ex))}
	}
	m.Metrics = res
	fmt.Printf("%v\n", res)
	if err := m.Save(*out); err != nil {
		panic(err)
	}
}

func round(x float64) float64 { return float64(int(x*10000+0.5)) / 10000 }

func answerAcc(m *gnn.Model, ex []semai.EventExample) float64 {
	semai.SetEventModel(m)
	ok, n := 0, 0
	for _, e := range ex {
		a := semai.SolveEvents(e.State, e.Question)
		n++
		if a != nil && a.Answer == e.Answer {
			ok++
		}
	}
	return float64(ok) / float64(n)
}
