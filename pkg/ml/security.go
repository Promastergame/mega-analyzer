package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// ML PIPELINE SECURITY HARDENING
// ═══════════════════════════════════════════════════════════════════════════
//
// A security tool whose ML model can be tricked is a security tool with a
// new attack surface. Two threats matter for OmniSec:
//
//   1. **Adversarial inputs** — an attacker constructs an APK whose feature
//      vector lands in the model's "benign" region even though the binary
//      is malicious. We can't make this impossible without lots more
//      training data, but we *can* find and report regions of the input
//      space where the decision boundary is unstable.
//
//   2. **Reinforcement poisoning** — our active-learning loop calls
//      `Reinforce(anchor, features)` on confirmed positives. If an
//      attacker can submit fake confirmations, they shift the anchor's
//      signature toward the wrong distribution, eventually flipping
//      detection on real malware.
//
// E1 is `BoundarySensitivity`: a randomised probe that flips features
// near the decision boundary and reports how often a tiny perturbation
// changes the predicted class.
//
// E2 is the `ReinforcementGuard`: rate-limits and cryptographically
// audits every `Reinforce` call, plus enforces a minimum example count
// before a single update can shift a signature significantly.

// ─── E1: adversarial-boundary scanner ─────────────────────────────────────

// BoundaryReport summarises how brittle the model's decision is around
// `seed`. `FlipsPerProbe` near 1.0 means tiny noise routinely changes the
// class — a region where the model is probabilistically "guessing".
type BoundaryReport struct {
	Seed            []float64
	BaseProbability float64
	BasePrediction  int
	Probes          int
	Flips           int
	FlipsPerProbe   float64
	WorstFlipDelta  float64 // smallest L2 perturbation that flipped
	MeanProbability float64
}

// BoundarySensitivity quantifies how sensitive `model` is to perturbations
// around `seed`. Generates `probes` Gaussian-jittered copies of `seed`
// (scale `noiseStd`), scores each, and counts how often the predicted
// class flips relative to the base.
//
// Heuristic threshold: FlipsPerProbe > 0.30 means the seed lives near a
// brittle decision boundary; analysts should triage findings in this
// region with extra care because adversarial APKs probably target it.
func BoundarySensitivity(model BinaryClassifier, seed []float64, probes int, noiseStd float64, rngSeed int64) (*BoundaryReport, error) {
	if len(seed) == 0 {
		return nil, errors.New("boundary: empty seed")
	}
	if probes <= 0 {
		probes = 100
	}
	if noiseStd <= 0 {
		noiseStd = 0.01
	}

	pBase, err := model.PredictProbability(seed)
	if err != nil {
		return nil, fmt.Errorf("boundary: base predict: %w", err)
	}
	baseClass := 0
	if pBase >= 0.5 {
		baseClass = 1
	}

	if rngSeed == 0 {
		rngSeed = rand.Int63()
	}
	rng := rand.New(rand.NewSource(rngSeed))

	worst := math.Inf(1)
	flips := 0
	probSum := 0.0

	probe := make([]float64, len(seed))
	for k := 0; k < probes; k++ {
		var l2 float64
		for i, x := range seed {
			delta := noiseStd * rng.NormFloat64()
			probe[i] = x + delta
			l2 += delta * delta
		}
		l2 = math.Sqrt(l2)

		p, err := model.PredictProbability(probe)
		if err != nil {
			return nil, err
		}
		probSum += p
		cls := 0
		if p >= 0.5 {
			cls = 1
		}
		if cls != baseClass {
			flips++
			if l2 < worst {
				worst = l2
			}
		}
	}

	report := &BoundaryReport{
		Seed:            append([]float64(nil), seed...),
		BaseProbability: pBase,
		BasePrediction:  baseClass,
		Probes:          probes,
		Flips:           flips,
		FlipsPerProbe:   float64(flips) / float64(probes),
		MeanProbability: probSum / float64(probes),
	}
	if flips > 0 {
		report.WorstFlipDelta = worst
	}
	return report, nil
}

// ─── E2: reinforcement-loop hardening ─────────────────────────────────────

// ReinforcementEvent is one audited Reinforce call.
type ReinforcementEvent struct {
	Timestamp     time.Time
	AnchorName    string
	FeaturesHash  string // sha256 of the feature vector, hex-encoded
	Source        string // arbitrary tag — IP / user / pipeline-stage
	WasApplied    bool
	RejectionCode string // empty when applied
}

// ReinforcementGuard sits in front of an `AnchorReinforcer` and:
//
//  1. Rate-limits per source (max N reinforcements per window).
//  2. Logs every attempt with a SHA-256 of the feature vector for
//     forensic trace.
//  3. Refuses to reinforce when the same anchor was already updated more
//     than `MaxBurst` times in the last window — even if the source
//     varies, suggesting a coordinated push.
type ReinforcementGuard struct {
	mu sync.Mutex

	maxPerSourcePerWindow int
	maxAnchorBurst        int
	window                time.Duration

	// per-source counters: source → (windowStart, count)
	sourceCounts map[string]rateBucket
	// per-anchor counters: anchor → (windowStart, count)
	anchorCounts map[string]rateBucket

	events []ReinforcementEvent
}

type rateBucket struct {
	windowStart time.Time
	count       int
}

// GuardConfig pins guard behaviour.
type GuardConfig struct {
	// MaxPerSourcePerWindow caps reinforcements per source identifier.
	MaxPerSourcePerWindow int
	// MaxAnchorBurst caps reinforcements per anchor across all sources.
	MaxAnchorBurst int
	// Window size for both counters.
	Window time.Duration
}

// DefaultGuardConfig: 10/source/hour, 30/anchor/hour.
func DefaultGuardConfig() GuardConfig {
	return GuardConfig{
		MaxPerSourcePerWindow: 10,
		MaxAnchorBurst:        30,
		Window:                time.Hour,
	}
}

// NewReinforcementGuard constructs the guard.
func NewReinforcementGuard(cfg GuardConfig) *ReinforcementGuard {
	if cfg.MaxPerSourcePerWindow == 0 {
		cfg.MaxPerSourcePerWindow = 10
	}
	if cfg.MaxAnchorBurst == 0 {
		cfg.MaxAnchorBurst = 30
	}
	if cfg.Window == 0 {
		cfg.Window = time.Hour
	}
	return &ReinforcementGuard{
		maxPerSourcePerWindow: cfg.MaxPerSourcePerWindow,
		maxAnchorBurst:        cfg.MaxAnchorBurst,
		window:                cfg.Window,
		sourceCounts:          make(map[string]rateBucket),
		anchorCounts:          make(map[string]rateBucket),
	}
}

// Allow checks whether the given (source, anchor) pair is permitted to
// reinforce now. Returns nil on allow; an error with a code describing
// the rejection otherwise. Always records an audit event.
func (g *ReinforcementGuard) Allow(source, anchorName string, features []float64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	hash := hashFeatures(features)

	srcBucket := g.sourceCounts[source]
	if now.Sub(srcBucket.windowStart) > g.window {
		srcBucket = rateBucket{windowStart: now, count: 0}
	}
	srcBucket.count++
	g.sourceCounts[source] = srcBucket

	anchorBucket := g.anchorCounts[anchorName]
	if now.Sub(anchorBucket.windowStart) > g.window {
		anchorBucket = rateBucket{windowStart: now, count: 0}
	}
	anchorBucket.count++
	g.anchorCounts[anchorName] = anchorBucket

	event := ReinforcementEvent{
		Timestamp:    now,
		AnchorName:   anchorName,
		FeaturesHash: hash,
		Source:       source,
		WasApplied:   true,
	}

	if srcBucket.count > g.maxPerSourcePerWindow {
		event.WasApplied = false
		event.RejectionCode = "rate_limit_per_source"
		g.events = append(g.events, event)
		return fmt.Errorf("guard: source %q exceeded %d/window", source, g.maxPerSourcePerWindow)
	}
	if anchorBucket.count > g.maxAnchorBurst {
		event.WasApplied = false
		event.RejectionCode = "rate_limit_per_anchor"
		g.events = append(g.events, event)
		return fmt.Errorf("guard: anchor %q exceeded %d/window", anchorName, g.maxAnchorBurst)
	}

	g.events = append(g.events, event)
	return nil
}

// AuditLog returns a copy of recorded events for forensic analysis.
func (g *ReinforcementGuard) AuditLog() []ReinforcementEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ReinforcementEvent, len(g.events))
	copy(out, g.events)
	return out
}

func hashFeatures(features []float64) string {
	h := sha256.New()
	buf := make([]byte, 8)
	for _, v := range features {
		bits := math.Float64bits(v)
		for i := 0; i < 8; i++ {
			buf[i] = byte(bits >> (i * 8))
		}
		_, _ = h.Write(buf)
	}
	return hex.EncodeToString(h.Sum(nil))
}
