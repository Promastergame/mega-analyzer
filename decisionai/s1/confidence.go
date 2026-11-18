package s1

import "math"

// ChoiceConfidence = (n*pmax - 1)/(n - 1): 1 when all mass is on one option, 0 when uniform.
func ChoiceConfidence(p []float64) float64 {
	n := len(p)
	if n < 2 {
		return 1
	}
	mx := 0.0
	for _, v := range p {
		mx = math.Max(mx, v)
	}
	return clamp01((float64(n)*mx - 1) / float64(n-1))
}

// ScoreConfidence = 1 - E|i - peak| / (that spread for a uniform distribution measured from the middle).
// Mass on neighbouring levels lowers confidence less than mass far away.
func ScoreConfidence(p []float64) float64 {
	n := len(p)
	if n < 2 {
		return 1
	}
	peak := 0
	for i := range p {
		if p[i] > p[peak] {
			peak = i
		}
	}
	spread, even := 0.0, 0.0
	mid := float64(n-1) / 2
	for i, v := range p {
		spread += v * math.Abs(float64(i-peak))
		even += math.Abs(float64(i) - mid)
	}
	even /= float64(n)
	if even == 0 {
		return 1
	}
	return clamp01(1 - spread/even)
}

// NoulCertainty maps a yes-probability to a 0..1 certainty used only for routing.
func NoulCertainty(p float64) float64 { return clamp01(math.Abs(p-0.5) * 2) }

// DefaultRoute is the three-path pattern: act / review / route to a human.
func DefaultRoute(certainty float64) string {
	switch {
	case certainty >= 0.8:
		return "auto"
	case certainty >= 0.5:
		return "review"
	default:
		return "human"
	}
}

func clamp01(x float64) float64 {
	if math.IsNaN(x) {
		return 0
	}
	return math.Max(0, math.Min(1, x))
}
func round4(x float64) float64 { return math.Round(x*1e4) / 1e4 }

func softmax(z []float64, temp float64) []float64 {
	if temp <= 0 {
		temp = 1
	}
	mx := math.Inf(-1)
	for _, v := range z {
		mx = math.Max(mx, v/temp)
	}
	out := make([]float64, len(z))
	s := 0.0
	for i, v := range z {
		out[i] = math.Exp(v/temp - mx)
		s += out[i]
	}
	for i := range out {
		out[i] /= s
	}
	return out
}
func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }
