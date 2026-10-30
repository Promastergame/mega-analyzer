package vulnscan

import (
	"sync"
	"time"
)

// PIDController dynamically adjusts the request delay based on server response time
type PIDController struct {
	mu           sync.Mutex
	Kp, Ki, Kd   float64
	targetRTT    float64
	integral     float64
	lastError    float64
	lastTime     time.Time
	currentDelay time.Duration
	maxRPS       int
}

func NewPIDController(targetRTTMs float64, maxRPS int) *PIDController {
	delay := time.Second / time.Duration(maxRPS)
	if maxRPS <= 0 {
		delay = 0
	}
	return &PIDController{
		Kp:           0.1,
		Ki:           0.01,
		Kd:           0.05,
		targetRTT:    targetRTTMs,
		lastTime:     time.Now(),
		currentDelay: delay,
		maxRPS:       maxRPS,
	}
}

// Observe measures the actual RTT and updates the delay
func (p *PIDController) Observe(actualRTT time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	dt := now.Sub(p.lastTime).Seconds()
	if dt <= 0 {
		dt = 0.001
	}

	actualRTTMs := float64(actualRTT.Milliseconds())
	// Error is positive if server is slower than target (need more delay)
	error := actualRTTMs - p.targetRTT

	p.integral += error * dt
	derivative := (error - p.lastError) / dt

	output := p.Kp*error + p.Ki*p.integral + p.Kd*derivative

	// output represents the suggested change in delay in milliseconds
	newDelayMs := float64(p.currentDelay.Milliseconds()) + output

	// Constrain to positive delay and respect maxRPS
	minDelayMs := float64(0)
	if p.maxRPS > 0 {
		minDelayMs = float64(1000 / p.maxRPS)
	}

	if newDelayMs < minDelayMs {
		newDelayMs = minDelayMs
	}
	if newDelayMs > 5000 { // Max 5 seconds delay
		newDelayMs = 5000
	}

	p.currentDelay = time.Duration(newDelayMs) * time.Millisecond
	p.lastError = error
	p.lastTime = now
}

// Wait blocks for the current computed delay to enforce rate limiting
func (p *PIDController) Wait() {
	p.mu.Lock()
	delay := p.currentDelay
	p.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
}

// WaitAndLimit limits concurrent execution
func (p *PIDController) Delay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentDelay
}
