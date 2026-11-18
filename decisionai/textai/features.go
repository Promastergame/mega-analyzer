package textai

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

type sparse map[int]float64

func words(s string) []string {
	xs := strings.FieldsFunc(strings.ToLower(s), func(c rune) bool { return !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' })
	if len(xs) > 2048 {
		xs = xs[:2048]
	}
	return xs
}
func slot(s string) (int, float64) {
	h := uint64(14695981039346656037)
	for _, b := range []byte(s) {
		h ^= uint64(b)
		h *= 1099511628211
	}
	sign := 1.0
	if h&(1<<63) != 0 {
		sign = -1
	}
	return int(h % Dims), sign
}
func terms(r Request) map[string]float64 {
	out := map[string]float64{}
	for _, f := range []struct {
		name, text string
		weight     float64
	}{{"state", r.State, 2}, {"question", r.Question, 1}, {"true", r.TrueWhen, 1}, {"false", r.FalseWhen, 1}} {
		ws := words(f.text)
		for i, w := range ws {
			out[f.name+":"+w] += f.weight
			if i > 0 {
				out[f.name+":"+ws[i-1]+" "+w] += f.weight
			}
		}
	}
	return out
}
func raw(ts map[string]float64) sparse {
	x := sparse{}
	keys := make([]string, 0, len(ts))
	for k := range ts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		i, sign := slot(k)
		x[i] += sign * (1 + math.Log(ts[k]))
	}
	return x
}
func weighted(x sparse, idf []float64) sparse {
	out := sparse{}
	keys := make([]int, 0, len(x))
	for i := range x {
		keys = append(keys, i)
	}
	sort.Ints(keys)
	norm := 0.0
	for _, i := range keys {
		v := x[i] * idf[i]
		out[i] = v
		norm += v * v
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for i, v := range out {
			out[i] = v / norm
		}
	}
	return out
}
func dot(w []float64, x sparse, b float64) float64 {
	keys := make([]int, 0, len(x))
	for i := range x {
		keys = append(keys, i)
	}
	sort.Ints(keys)
	for _, i := range keys {
		b += w[i] * x[i]
	}
	return b
}
func sigmoid(v float64) float64 {
	if v >= 0 {
		return 1 / (1 + math.Exp(-v))
	}
	e := math.Exp(v)
	return e / (1 + e)
}
func fieldsSignature(r Request) string {
	return SHA256(r.TaskID + "\x00" + r.State + "\x00" + r.Question + "\x00" + r.TrueWhen + "\x00" + r.FalseWhen)
}
func contributions(ts map[string]float64, x sparse, m *Model) []Contribution {
	out := []Contribution{}
	buckets := raw(ts)
	for k, v := range ts {
		i, sign := slot(k)
		normalizer := 0.0
		if x[i] != 0 { // individual shares in a hashed bucket; collisions are explicitly flagged in docs.
			rawBucket := buckets[i]
			if rawBucket != 0 {
				normalizer = x[i] / rawBucket
			}
		}
		c := m.CalibrationA * m.Weights[i] * sign * (1 + math.Log(v)) * normalizer
		if math.Abs(c) > 1e-9 {
			out = append(out, Contribution{k, c})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := math.Abs(out[i].Contribution), math.Abs(out[j].Contribution)
		if a == b {
			return out[i].Feature < out[j].Feature
		}
		return a > b
	})
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}
