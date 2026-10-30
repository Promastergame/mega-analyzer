package vulnscan

import (
	"context"
	"sync"
)

// AIMDController implements Additive-Increase / Multiplicative-Decrease
// concurrency control - the same congestion-control principle TCP has used
// for 40 years. It replaces the hand-tuned PID controller, which required
// arbitrary gain calibration and ignored server error signals (429/503).
//
// Concurrency additively increases after a run of successes and multiplicatively
// collapses on server pressure. A cond var gates goroutines so the *live*
// concurrency limit is enforced even as it shrinks mid-flight.
type AIMDController struct {
	mu   sync.Mutex
	cond *sync.Cond

	concurrency    int
	minConcurrency int
	maxConcurrency int
	inFlight       int

	successWindow    int
	successThreshold int
	backoffFactor    float64
}

// NewAIMDController creates a controller starting at `initial` permits and
// never exceeding `max`.
func NewAIMDController(initial, max int) *AIMDController {
	if max < 1 {
		max = 1
	}
	if initial < 1 {
		initial = 1
	}
	if initial > max {
		initial = max
	}
	a := &AIMDController{
		concurrency:      initial,
		minConcurrency:   1,
		maxConcurrency:   max,
		successThreshold: 10,
		backoffFactor:    0.5,
	}
	a.cond = sync.NewCond(&a.mu)
	return a
}

// Acquire blocks until a permit is available or the context is cancelled.
func (a *AIMDController) Acquire(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for a.inFlight >= a.concurrency {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
		// Wake periodically via broadcast on state change.
		a.cond.Wait()
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
	}
	a.inFlight++
	return nil
}

// Release returns a permit.
func (a *AIMDController) Release() {
	a.mu.Lock()
	if a.inFlight > 0 {
		a.inFlight--
	}
	a.cond.Broadcast()
	a.mu.Unlock()
}

// OnSuccess records a successful interaction; additively increases capacity.
func (a *AIMDController) OnSuccess() {
	a.mu.Lock()
	a.successWindow++
	if a.successWindow >= a.successThreshold {
		if a.concurrency < a.maxConcurrency {
			a.concurrency++
		}
		a.successWindow = 0
	}
	a.cond.Broadcast()
	a.mu.Unlock()
}

// OnServerPressure records a 429/503/timeout; multiplicatively decreases.
func (a *AIMDController) OnServerPressure() {
	a.mu.Lock()
	next := int(float64(a.concurrency) * a.backoffFactor)
	if next < a.minConcurrency {
		next = a.minConcurrency
	}
	a.concurrency = next
	a.successWindow = 0
	a.cond.Broadcast()
	a.mu.Unlock()
}

// Concurrency returns the current permit ceiling.
func (a *AIMDController) Concurrency() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.concurrency
}

// IsServerPressure classifies an HTTP status as backpressure.
func IsServerPressure(status int) bool {
	return status == 429 || status == 503 || status == 502 || status == 504
}
