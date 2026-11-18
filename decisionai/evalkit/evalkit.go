// Package evalkit measures decision models the way they are used: not only "how often right",
// but "is the stated confidence honest" and "how much can be automated at a given risk".
package evalkit

import (
	"math"
	"sort"
)

// Pred is one decision: the chosen label, its confidence, whether it was right.
// Abstained predictions (the model said "unknown") count against coverage, not accuracy.
type Pred struct {
	Conf      float64   `json:"conf"`
	Correct   bool      `json:"correct"`
	Abstained bool      `json:"abstained,omitempty"`
	Label     int       `json:"-"`
	Gold      int       `json:"-"`
	Probs     []float64 `json:"-"` // full distribution (optional, for NLL/Brier)
}

type Bin struct {
	Lo, Hi   float64
	N        int
	Conf     float64 `json:"mean_conf"`
	Accuracy float64 `json:"accuracy"`
}

type Point struct {
	Threshold float64 `json:"threshold"`
	Coverage  float64 `json:"coverage"`
	Accuracy  float64 `json:"accuracy"`
	N         int     `json:"n"`
}

type Report struct {
	Name       string   `json:"name"`
	Note       string   `json:"note,omitempty"`
	N          int      `json:"n"`
	Answered   int      `json:"answered"`
	Accuracy   float64  `json:"accuracy"`     // over answered
	AccAll     float64  `json:"accuracy_all"` // abstain = wrong
	MacroF1    float64  `json:"macro_f1,omitempty"`
	NLL        float64  `json:"nll,omitempty"`
	Brier      float64  `json:"brier,omitempty"`
	ECE        float64  `json:"ece"`
	AURC       float64  `json:"aurc"`           // area under risk-coverage (lower = better)
	Cov95      float64  `json:"coverage_at_95"` // largest coverage with accuracy >= 95%
	Cov99      float64  `json:"coverage_at_99"`
	Bins       []Bin    `json:"reliability"`
	Curve      []Point  `json:"selective"`
	Confusions []string `json:"top_confusions,omitempty"`
}

// Compute builds a report. classes (optional) names labels for macro-F1 / confusions.
func Compute(name string, ps []Pred, classes []string) Report {
	r := Report{Name: name, N: len(ps)}
	var ans []Pred
	for _, p := range ps {
		if !p.Abstained {
			ans = append(ans, p)
		}
	}
	r.Answered = len(ans)
	hit := 0
	for _, p := range ans {
		if p.Correct {
			hit++
		}
	}
	if len(ans) > 0 {
		r.Accuracy = round(float64(hit) / float64(len(ans)))
	}
	if len(ps) > 0 {
		r.AccAll = round(float64(hit) / float64(len(ps)))
	}
	// reliability, 10 bins
	bins := make([]Bin, 10)
	for i := range bins {
		bins[i].Lo, bins[i].Hi = float64(i)/10, float64(i+1)/10
	}
	acc := make([]float64, 10)
	for _, p := range ans {
		k := min(int(p.Conf*10), 9)
		bins[k].N++
		bins[k].Conf += p.Conf
		if p.Correct {
			acc[k]++
		}
	}
	for i := range bins {
		if bins[i].N > 0 {
			n := float64(bins[i].N)
			r.ECE += math.Abs(bins[i].Conf-acc[i]) / float64(max(len(ans), 1))
			bins[i].Conf, bins[i].Accuracy = round(bins[i].Conf/n), round(acc[i]/n)
		}
	}
	r.ECE = round(r.ECE)
	r.Bins = bins
	// selective curve
	for _, t := range []float64{0, .5, .6, .7, .8, .9, .95, .99} {
		n, h := 0, 0
		for _, p := range ans {
			if p.Conf >= t {
				n++
				if p.Correct {
					h++
				}
			}
		}
		pt := Point{Threshold: t, N: n, Coverage: round(float64(n) / float64(max(len(ps), 1)))}
		if n > 0 {
			pt.Accuracy = round(float64(h) / float64(n))
		}
		r.Curve = append(r.Curve, pt)
	}
	// AURC + coverage at target accuracy: sort by confidence desc
	s := append([]Pred(nil), ans...)
	sort.SliceStable(s, func(i, j int) bool { return s[i].Conf > s[j].Conf })
	h := 0
	for i, p := range s {
		if p.Correct {
			h++
		}
		risk := 1 - float64(h)/float64(i+1)
		r.AURC += risk / float64(len(ps))
		a, cov := float64(h)/float64(i+1), float64(i+1)/float64(len(ps))
		if a >= 0.95 {
			r.Cov95 = cov
		}
		if a >= 0.99 {
			r.Cov99 = cov
		}
	}
	r.AURC, r.Cov95, r.Cov99 = round(r.AURC), round(r.Cov95), round(r.Cov99)
	// binary Brier of the stated confidence when no full distribution is given
	if len(ans) > 0 && ans[0].Probs == nil {
		for _, p := range ans {
			y := 0.0
			if p.Correct {
				y = 1
			}
			r.Brier += (p.Conf - y) * (p.Conf - y)
		}
		r.Brier = round(r.Brier / float64(len(ans)))
	}
	// NLL / Brier / F1 when distributions are given
	if len(ans) > 0 && ans[0].Probs != nil {
		C := len(ans[0].Probs)
		tp, fp, fn := make([]float64, C), make([]float64, C), make([]float64, C)
		conf := map[[2]int]int{}
		for _, p := range ans {
			r.NLL -= math.Log(math.Max(p.Probs[p.Gold], 1e-12))
			for k, q := range p.Probs {
				y := 0.0
				if k == p.Gold {
					y = 1
				}
				r.Brier += (q - y) * (q - y)
			}
			if p.Label == p.Gold {
				tp[p.Label]++
			} else {
				fp[p.Label]++
				fn[p.Gold]++
				conf[[2]int{p.Gold, p.Label}]++
			}
		}
		n := float64(len(ans))
		r.NLL, r.Brier = round(r.NLL/n), round(r.Brier/n)
		f1, cnt := 0.0, 0.0
		for c := 0; c < C; c++ {
			if tp[c]+fn[c] == 0 {
				continue
			}
			pr, rc := tp[c]/math.Max(tp[c]+fp[c], 1), tp[c]/(tp[c]+fn[c])
			if pr+rc > 0 {
				f1 += 2 * pr * rc / (pr + rc)
			}
			cnt++
		}
		r.MacroF1 = round(f1 / math.Max(cnt, 1))
		type kv struct {
			k [2]int
			v int
		}
		var cs []kv
		for k, v := range conf {
			cs = append(cs, kv{k, v})
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].v > cs[j].v })
		for i, c := range cs {
			if i == 5 {
				break
			}
			a, b := itoa(c.k[0]), itoa(c.k[1])
			if classes != nil {
				a, b = classes[c.k[0]], classes[c.k[1]]
			}
			r.Confusions = append(r.Confusions, a+" → "+b+": "+itoa(c.v))
		}
	}
	return r
}

// FromProbs makes a Pred from a distribution and the gold label (abstain below thr when thr > 0).
func FromProbs(p []float64, gold int, thr float64) Pred {
	b := 0
	for i := range p {
		if p[i] > p[b] {
			b = i
		}
	}
	return Pred{Conf: p[b], Correct: b == gold, Label: b, Gold: gold, Probs: p, Abstained: thr > 0 && p[b] < thr}
}

func round(x float64) float64 { return math.Round(x*10000) / 10000 }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
