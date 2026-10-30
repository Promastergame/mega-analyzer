package labkit

import (
	"math/rand/v2"
	"sync"
	"time"
)

// FaultKind classifies an injected fault produced by a Scenario.
type FaultKind int

// The set of faults a Scenario can inject.
const (
	FaultNone FaultKind = iota
	// FaultError asks the caller to return an error response (HTTP status,
	// TCP connection reset, etc.).
	FaultError
	// FaultTimeout asks the caller to stall for Outcome.Latency and then hang
	// up, simulating an unresponsive upstream.
	FaultTimeout
)

// ScenarioConfig declares repeatable, injectable behaviour. All fields are
// optional; the zero value is a pass-through scenario that injects nothing.
type ScenarioConfig struct {
	// FixedLatency is added to every response.
	FixedLatency Duration `json:"fixed_latency"`
	// JitterLatency adds a uniform random delay in [0, JitterLatency).
	JitterLatency Duration `json:"jitter_latency"`
	// ErrorRate is the probability in [0,1] of injecting FaultError.
	ErrorRate float64 `json:"error_rate"`
	// ErrorStatus is the HTTP status used for injected errors (default 503).
	ErrorStatus int `json:"error_status"`
	// TimeoutRate is the probability in [0,1] of injecting FaultTimeout.
	TimeoutRate float64 `json:"timeout_rate"`
	// TimeoutDuration is how long a FaultTimeout stalls before hanging up.
	TimeoutDuration Duration `json:"timeout_duration"`
	// Seed makes fault selection deterministic. A zero seed selects a
	// time-based seed (non-reproducible).
	Seed uint64 `json:"seed"`
}

// Outcome is the result of rolling a Scenario for a single request.
type Outcome struct {
	Latency time.Duration
	Fault   FaultKind
	Status  int
}

// Scenario turns a ScenarioConfig into repeatable per-request decisions. It is
// safe for concurrent use; the random source is guarded by a mutex so that a
// fixed Seed yields a deterministic sequence regardless of goroutine timing.
type Scenario struct {
	cfg ScenarioConfig
	mu  sync.Mutex
	rng *rand.Rand
}

// NewScenario builds a Scenario from cfg, applying safe defaults.
func NewScenario(cfg ScenarioConfig) *Scenario {
	if cfg.ErrorStatus == 0 {
		cfg.ErrorStatus = 503
	}
	if cfg.TimeoutDuration == 0 {
		cfg.TimeoutDuration = Duration(5 * time.Second)
	}
	seed := cfg.Seed
	seed2 := seed
	if seed == 0 {
		now := uint64(time.Now().UnixNano())
		seed, seed2 = now, now^0x9e3779b97f4a7c15
	}
	return &Scenario{cfg: cfg, rng: rand.New(rand.NewPCG(seed, seed2))}
}

// Config returns the effective configuration (with defaults applied).
func (s *Scenario) Config() ScenarioConfig { return s.cfg }

// Roll produces one Outcome. Latency is always computed; Fault is selected
// from the configured error/timeout probabilities.
func (s *Scenario) Roll() Outcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := Outcome{Status: s.cfg.ErrorStatus, Latency: s.cfg.FixedLatency.D()}
	if s.cfg.JitterLatency > 0 {
		out.Latency += time.Duration(s.rng.Int64N(int64(s.cfg.JitterLatency.D())))
	}

	r := s.rng.Float64()
	switch {
	case s.cfg.ErrorRate > 0 && r < s.cfg.ErrorRate:
		out.Fault = FaultError
	case s.cfg.TimeoutRate > 0 && r < s.cfg.ErrorRate+s.cfg.TimeoutRate:
		out.Fault = FaultTimeout
		if s.cfg.TimeoutDuration.D() > out.Latency {
			out.Latency = s.cfg.TimeoutDuration.D()
		}
	}
	return out
}
