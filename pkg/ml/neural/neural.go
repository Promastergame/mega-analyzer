package neural

import (
	"math"
	"sort"
	"strings"
	"time"
)

// Event models one sandbox observation.
type Event struct {
	At      time.Time
	Kind    string
	Subject string
	Value   float64
}

// TimelineEncoder turns events into a small fixed embedding.
type TimelineEncoder struct {
	Buckets int
}

// Encode returns a stable summary vector over a session timeline.
func (e TimelineEncoder) Encode(events []Event) []float64 {
	if e.Buckets <= 0 {
		e.Buckets = 8
	}
	vec := make([]float64, e.Buckets+4)
	if len(events) == 0 {
		return vec
	}

	first := events[0].At
	last := events[0].At
	for _, ev := range events[1:] {
		if ev.At.Before(first) {
			first = ev.At
		}
		if ev.At.After(last) {
			last = ev.At
		}
	}

	window := last.Sub(first)
	if window <= 0 {
		window = time.Second
	}

	for _, ev := range events {
		pos := int(float64(ev.At.Sub(first)) / float64(window) * float64(e.Buckets-1))
		if pos < 0 {
			pos = 0
		}
		if pos >= e.Buckets {
			pos = e.Buckets - 1
		}
		vec[pos]++
		vec[e.Buckets] += ev.Value
		vec[e.Buckets+1] += 1
		if strings.Contains(strings.ToLower(ev.Kind), "network") || strings.Contains(strings.ToLower(ev.Kind), "dns") {
			vec[e.Buckets+2]++
		}
		if strings.Contains(strings.ToLower(ev.Kind), "file") || strings.Contains(strings.ToLower(ev.Kind), "reg") {
			vec[e.Buckets+3]++
		}
	}

	scale := 1.0 / float64(len(events))
	for i := range vec {
		vec[i] *= scale
	}
	return vec
}

// Similarity computes cosine similarity between two embeddings.
func Similarity(a, b []float64) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// AnomalyScore estimates how far a session is from the baseline.
type AnomalyScore struct {
	Mean   []float64
	StdDev []float64
}

// Score returns a [0,1] anomaly estimate.
func (a AnomalyScore) Score(x []float64) float64 {
	if len(a.Mean) == 0 || len(a.Mean) != len(x) || len(a.StdDev) != len(x) {
		return 0
	}
	var z float64
	for i := range x {
		std := a.StdDev[i]
		if std <= 0 {
			std = 1
		}
		d := (x[i] - a.Mean[i]) / std
		z += d * d
	}
	return 1 - math.Exp(-math.Sqrt(z)/3.0)
}

// Fusion blends multiple model outputs into one risk score.
type Fusion struct {
	WTimeline   float64
	WSimilarity float64
	WAnomaly    float64
	WStatic     float64
	WSandbox    float64
}

// DefaultFusion returns sane weights.
func DefaultFusion() Fusion {
	return Fusion{
		WTimeline:   0.22,
		WSimilarity: 0.18,
		WAnomaly:    0.22,
		WStatic:     0.20,
		WSandbox:    0.18,
	}
}

// Score returns a fused [0,100] risk estimate.
func (f Fusion) Score(timeline, similarity, anomaly, static, sandbox float64) float64 {
	raw := timeline*f.WTimeline + similarity*f.WSimilarity + anomaly*f.WAnomaly + static*f.WStatic + sandbox*f.WSandbox
	if raw < 0 {
		raw = 0
	}
	if raw > 1 {
		raw = 1
	}
	return raw * 100
}

// Fingerprint extracts a stable event-token summary.
func Fingerprint(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		token := strings.ToLower(ev.Kind + ":" + ev.Subject)
		if token != ":" {
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}
