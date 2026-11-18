// smali-gnn trains the literal-role GNN on an apktool corpus and compares it with the bundled
// logistic model on the same held-out apps (same split as `smali-role train`).
package main

import (
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"decisionai/gnn"
	"decisionai/smalirole"
)

func split(app string) int {
	h := sha1.Sum([]byte(app))
	switch v := int(h[0]) % 10; {
	case v < 6:
		return 0
	case v < 8:
		return 1
	}
	return 2
}

type stat struct {
	N                  int
	Acc, MacroF1, ECE  float64
	SelAcc80, SelCov80 float64
}

func evaluate(probs [][]float64, ys []int) stat {
	C := len(smalirole.Labels)
	tp, fp, fn := make([]float64, C), make([]float64, C), make([]float64, C)
	bins := make([][3]float64, 15)
	hit, selN, selHit := 0.0, 0.0, 0.0
	for i, p := range probs {
		b := 0
		for j := range p {
			if p[j] > p[b] {
				b = j
			}
		}
		h := 0.0
		if b == ys[i] {
			h = 1
			tp[b]++
		} else {
			fp[b]++
			fn[ys[i]]++
		}
		hit += h
		k := min(int(p[b]*15), 14)
		bins[k][0] += p[b]
		bins[k][1] += h
		bins[k][2]++
		if p[b] >= 0.8 {
			selN++
			selHit += h
		}
	}
	n := float64(len(ys))
	s := stat{N: len(ys), Acc: hit / n, SelCov80: selN / n, SelAcc80: selHit / math.Max(selN, 1)}
	f1, cnt := 0.0, 0.0
	for c := 0; c < C; c++ {
		if tp[c]+fn[c] == 0 {
			continue
		}
		pr := tp[c] / math.Max(tp[c]+fp[c], 1)
		rc := tp[c] / (tp[c] + fn[c])
		if pr+rc > 0 {
			f1 += 2 * pr * rc / (pr + rc)
		}
		cnt++
	}
	s.MacroF1 = f1 / cnt
	for _, b := range bins {
		if b[2] > 0 {
			s.ECE += math.Abs(b[0]-b[1]) / n
		}
	}
	return s
}

func main() {
	root := flag.String("root", "/data/corpus/dec", "corpus of apktool dirs")
	capN := flag.Int("cap", 300, "per label per app")
	epochs := flag.Int("epochs", 8, "epochs")
	hidden := flag.Int("hidden", 32, "hidden")
	lrModel := flag.String("lr", "models/smalirole-model.json", "baseline LR model")
	out := flag.String("out", "models/smalirole-gnn.json", "output")
	flag.Parse()
	t0 := time.Now()
	ex, err := smalirole.GraphDataset(*root, *capN)
	if err != nil {
		panic(err)
	}
	var parts [3][]smalirole.GraphExample
	for _, e := range ex {
		k := split(e.App)
		parts[k] = append(parts[k], e)
	}
	fmt.Fprintf(os.Stderr, "dataset %d/%d/%d (%s)\n", len(parts[0]), len(parts[1]), len(parts[2]), time.Since(t0).Round(time.Second))
	gs := func(p []smalirole.GraphExample, full bool) []*gnn.Graph {
		var o []*gnn.Graph
		for _, e := range p {
			if full {
				o = append(o, e.Full)
			} else {
				o = append(o, e.Graph)
			}
		}
		return o
	}
	train, cal := gs(parts[0], false), gs(parts[1], false)
	m := gnn.New(smalirole.Labels, 1<<13, *hidden, smalirole.SiteRelations, 2, 3)
	m.Train(train, gnn.TrainOptions{Epochs: *epochs, LR: 0.003, Batch: 32, L2: 1e-6, Seed: 1, Verbose: func(ep int, loss float64) {
		acc, _, _ := m.Eval(cal[:min(3000, len(cal))])
		fmt.Fprintf(os.Stderr, "epoch %d loss %.4f cal-acc %.4f (%s)\n", ep+1, loss/float64(len(train)), acc, time.Since(t0).Round(time.Second))
	}})
	m.FitTemperature(cal)
	var ys []int
	var pg, pgFull, plr, pmix [][]float64
	lr, err := smalirole.LoadModel(*lrModel)
	if err != nil {
		panic(err)
	}
	for _, e := range parts[2] {
		ys = append(ys, e.Label)
		a := m.Predict(e.Graph)[0]
		pg = append(pg, a)
		pgFull = append(pgFull, m.Predict(e.Full)[0])
		b := smalirole.Softmax(lr.Logits(e.Feats), lr.Temperature)
		plr = append(plr, b)
		mix := make([]float64, len(a))
		for i := range a {
			mix[i] = 0.5*a[i] + 0.5*b[i]
		}
		pmix = append(pmix, mix)
	}
	res := map[string]any{"test_apps_examples": len(ys), "temperature": m.Temperature,
		"gnn_masked": evaluate(pg, ys), "lr_masked": evaluate(plr, ys), "mix_masked": evaluate(pmix, ys), "gnn_full": evaluate(pgFull, ys)}
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
	m.Metrics = res
	if err := m.Save(*out); err != nil {
		panic(err)
	}
}
