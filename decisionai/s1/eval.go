package s1

import (
	"fmt"
	"math"
	"sort"
)

// TypeMetrics summarises quality for one question type against labels/reference probabilities.
type TypeMetrics struct {
	N             int     `json:"n"`
	Agreement     float64 `json:"agreement"`      // argmax matches label/reference argmax
	Brier         float64 `json:"brier"`          // multi-class Brier (sum of squares)
	LogLoss       float64 `json:"log_loss"`       // cross-entropy vs label/reference
	ECE           float64 `json:"ece"`            // 10-bin expected calibration error on top probability
	JSDivergence  float64 `json:"js_divergence"`  // vs reference distribution (bits), 0 = identical
	AutoRate      float64 `json:"auto_rate"`      // share routed "auto"
	AutoAgreement float64 `json:"auto_agreement"` // agreement among "auto" answers
	AgreementLow  float64 `json:"agreement_low"`  // 95% Wilson interval
	AgreementHigh float64 `json:"agreement_high"`
}

// EvalFailure identifies a wrong answer in the input dataset, without copying its state.
type EvalFailure struct {
	Example     int      `json:"example"` // 1-based input record
	Group       string   `json:"group,omitempty"`
	Question    string   `json:"question"`
	Type        string   `json:"type"`
	Expected    string   `json:"expected"`
	Predicted   string   `json:"predicted"`
	Probability float64  `json:"probability"`
	Route       string   `json:"route"`
	Source      string   `json:"source,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type SourceMetrics struct {
	N         int     `json:"n"`
	Agreement float64 `json:"agreement"`
}

type EvalReport struct {
	Version     string                               `json:"version"`
	Backend     string                               `json:"backend"`
	Calibration Calibration                          `json:"calibration"`
	Examples    int                                  `json:"examples"`
	Questions   int                                  `json:"questions"`
	ByType      map[string]TypeMetrics               `json:"by_type"`
	LatencyP50  float64                              `json:"latency_ms_p50"`
	LatencyP95  float64                              `json:"latency_ms_p95"`
	Errors      []string                             `json:"errors,omitempty"`
	Failures    []EvalFailure                        `json:"failures,omitempty"`
	BySource    map[string]SourceMetrics             `json:"by_source"`
	Confusion   map[string]map[string]map[string]int `json:"confusion"` // type -> expected -> predicted -> count
}

type scored struct {
	t      target
	route  string
	detail EvalFailure
}

func (e *Engine) collect(data []Labelled) ([]scored, []float64, []string) {
	var out []scored
	var lat []float64
	var errs []string
	for i, ex := range data {
		if err := e.ValidateLabelled(ex); err != nil {
			errs = append(errs, fmt.Sprintf("example %d: %v", i+1, err))
			continue
		}
		resp, err := e.Decide(ex.Request)
		if err != nil {
			errs = append(errs, fmt.Sprintf("example %d: %v", i, err))
			continue
		}
		lat = append(lat, resp.ElapsedMs)
		ids := make([]string, 0, len(ex.Labels))
		for id := range ex.Labels {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			raw := ex.Labels[id]
			a, ok := resp.Answers[id]
			if !ok {
				errs = append(errs, fmt.Sprintf("example %d: label for unknown question %q", i, id))
				continue
			}
			t, err := targetFor(a, raw)
			if err != nil {
				errs = append(errs, fmt.Sprintf("example %d/%s: %v", i, id, err))
				continue
			}
			source := a.Source
			if source == "" {
				source = e.Backend.Name()
			}
			out = append(out, scored{t: t, route: a.Route, detail: EvalFailure{
				Example: i + 1, Group: ex.Group, Question: id, Type: a.Type,
				Route: a.Route, Source: source, Evidence: a.Evidence,
			}})
		}
	}
	return out, lat, errs
}

// Calibrate fits per-type temperatures on data (run with unit temperatures).
func (e *Engine) Calibrate(data []Labelled) (Calibration, []string) {
	saved := e.Calib
	e.Calib = DefaultCalibration()
	sc, _, errs := e.collect(data)
	e.Calib = saved
	ts := make([]target, len(sc))
	for i := range sc {
		ts[i] = sc[i].t
	}
	c := FitTemperatures(ts)
	c.Fingerprint = e.ConfigurationFingerprint()
	return c, errs
}

// Evaluate measures the engine (with its current calibration) on labelled data.
func (e *Engine) Evaluate(data []Labelled) EvalReport {
	sc, lat, errs := e.collect(data)
	rep := EvalReport{Version: Version, Backend: e.Backend.Name(), Calibration: e.Calib, Examples: len(data), Questions: len(sc), ByType: map[string]TypeMetrics{}, Errors: errs}
	rep.BySource = map[string]SourceMetrics{}
	rep.Confusion = map[string]map[string]map[string]int{}
	byType := map[string][]scored{}
	for _, s := range sc {
		byType[s.t.typ] = append(byType[s.t.typ], s)
	}
	for typ, group := range byType {
		var m TypeMetrics
		type bin struct{ conf, acc, n float64 }
		bins := make([]bin, 10)
		auto, autoOK := 0.0, 0.0
		for _, s := range group {
			p := probsAt(s.t, e.Calib.temp(typ))
			pa, ta := argmax(p), argmax(s.t.dist)
			ok := 0.0
			if pa == ta {
				ok = 1
			}
			detail := s.detail
			detail.Expected, detail.Predicted = s.t.keys[ta], s.t.keys[pa]
			detail.Probability = round4(p[pa])
			if ok == 0 {
				rep.Failures = append(rep.Failures, detail)
			}
			source := rep.BySource[detail.Source]
			source.N++
			source.Agreement += ok
			rep.BySource[detail.Source] = source
			if rep.Confusion[typ] == nil {
				rep.Confusion[typ] = map[string]map[string]int{}
			}
			if rep.Confusion[typ][detail.Expected] == nil {
				rep.Confusion[typ][detail.Expected] = map[string]int{}
			}
			rep.Confusion[typ][detail.Expected][detail.Predicted]++
			m.Agreement += ok
			for i := range p {
				d := p[i] - s.t.dist[i]
				m.Brier += d * d
			}
			m.LogLoss += crossEntropy(s.t, p)
			m.JSDivergence += js(p, s.t.dist)
			b := int(math.Min(9, p[pa]*10))
			bins[b].conf += p[pa]
			bins[b].acc += ok
			bins[b].n++
			if s.route == "auto" {
				auto++
				autoOK += ok
			}
		}
		n := float64(len(group))
		m.N = len(group)
		m.Agreement /= n
		m.AgreementLow, m.AgreementHigh = wilson(m.Agreement, n)
		m.Brier /= n
		m.LogLoss /= n
		m.JSDivergence /= n
		for _, b := range bins {
			if b.n > 0 {
				m.ECE += b.n / n * math.Abs(b.acc/b.n-b.conf/b.n)
			}
		}
		m.AutoRate = auto / n
		if auto > 0 {
			m.AutoAgreement = autoOK / auto
		}
		for _, f := range []*float64{&m.Agreement, &m.Brier, &m.LogLoss, &m.ECE, &m.JSDivergence, &m.AutoRate, &m.AutoAgreement} {
			*f = round4(*f)
		}
		rep.ByType[typ] = m
	}
	for name, source := range rep.BySource {
		source.Agreement = round4(source.Agreement / float64(source.N))
		rep.BySource[name] = source
	}
	// Review confident mistakes first; break ties deterministically.
	sort.Slice(rep.Failures, func(i, j int) bool {
		a, b := rep.Failures[i], rep.Failures[j]
		if a.Probability != b.Probability {
			return a.Probability > b.Probability
		}
		if a.Example != b.Example {
			return a.Example < b.Example
		}
		return a.Question < b.Question
	})
	sort.Float64s(lat)
	rep.LatencyP50, rep.LatencyP95 = pct(lat, .5), pct(lat, .95)
	return rep
}

func wilson(p, n float64) (float64, float64) {
	const z = 1.959963984540054
	d := 1 + z*z/n
	center := (p + z*z/(2*n)) / d
	margin := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n)) / d
	return round4(math.Max(0, center-margin)), round4(math.Min(1, center+margin))
}

func argmax(p []float64) int {
	b := 0
	for i := range p {
		if p[i] > p[b] {
			b = i
		}
	}
	return b
}

func js(p, q []float64) float64 {
	kl := func(a, m []float64) float64 {
		s := 0.0
		for i := range a {
			if a[i] > 0 {
				s += a[i] * math.Log2(a[i]/math.Max(m[i], 1e-12))
			}
		}
		return s
	}
	m := make([]float64, len(p))
	for i := range p {
		m[i] = (p[i] + q[i]) / 2
	}
	return (kl(p, m) + kl(q, m)) / 2
}

func pct(s []float64, q float64) float64 {
	if len(s) == 0 {
		return 0
	}
	return s[int(math.Min(float64(len(s)-1), math.Floor(q*float64(len(s)))))]
}
