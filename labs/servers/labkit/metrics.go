package labkit

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// latencyBucketsNanos are upper bounds (inclusive) for the latency histogram,
// ranging from 100µs to 10s. Anything larger falls into an implicit overflow
// bucket. The bounds are fixed so percentile math needs no locking on the hot
// path — each observation is a single atomic increment.
var latencyBucketsNanos = [...]int64{
	100_000,        // 100µs
	250_000,        // 250µs
	500_000,        // 500µs
	1_000_000,      // 1ms
	2_500_000,      // 2.5ms
	5_000_000,      // 5ms
	10_000_000,     // 10ms
	25_000_000,     // 25ms
	50_000_000,     // 50ms
	100_000_000,    // 100ms
	250_000_000,    // 250ms
	500_000_000,    // 500ms
	1_000_000_000,  // 1s
	5_000_000_000,  // 5s
	10_000_000_000, // 10s
}

// Latency is a concurrency-safe streaming latency recorder. Observations are
// aggregated with atomics; no per-call allocation or lock is taken.
type Latency struct {
	count   atomic.Int64
	sum     atomic.Int64 // nanoseconds
	min     atomic.Int64 // nanoseconds; 0 means unset
	max     atomic.Int64 // nanoseconds
	buckets [len(latencyBucketsNanos) + 1]atomic.Int64
}

// Observe records a single duration.
func (l *Latency) Observe(d time.Duration) {
	n := d.Nanoseconds()
	if n < 0 {
		n = 0
	}
	l.count.Add(1)
	l.sum.Add(n)
	for {
		cur := l.min.Load()
		if cur != 0 && cur <= n {
			break
		}
		if l.min.CompareAndSwap(cur, n) {
			break
		}
	}
	for {
		cur := l.max.Load()
		if cur >= n {
			break
		}
		if l.max.CompareAndSwap(cur, n) {
			break
		}
	}
	idx := sort.Search(len(latencyBucketsNanos), func(i int) bool {
		return n <= latencyBucketsNanos[i]
	})
	l.buckets[idx].Add(1)
}

// LatencySummary is a point-in-time view of a Latency recorder. Durations are
// reported in milliseconds for readability.
type LatencySummary struct {
	Count  int64   `json:"count"`
	MeanMS float64 `json:"mean_ms"`
	MinMS  float64 `json:"min_ms"`
	MaxMS  float64 `json:"max_ms"`
	P50MS  float64 `json:"p50_ms"`
	P90MS  float64 `json:"p90_ms"`
	P99MS  float64 `json:"p99_ms"`
}

func (l *Latency) summary() LatencySummary {
	count := l.count.Load()
	s := LatencySummary{Count: count}
	if count == 0 {
		return s
	}
	s.MeanMS = float64(l.sum.Load()) / float64(count) / 1e6
	s.MinMS = float64(l.min.Load()) / 1e6
	s.MaxMS = float64(l.max.Load()) / 1e6
	s.P50MS = l.percentileMS(0.50, count)
	s.P90MS = l.percentileMS(0.90, count)
	s.P99MS = l.percentileMS(0.99, count)
	return s
}

// percentileMS returns the upper bound (in ms) of the histogram bucket that
// contains the requested quantile. It is an approximation bounded by the
// bucket resolution, which is plenty for latency-injection experiments.
func (l *Latency) percentileMS(q float64, count int64) float64 {
	target := int64(q * float64(count))
	if target < 1 {
		target = 1
	}
	var cum int64
	for i := 0; i < len(l.buckets); i++ {
		cum += l.buckets[i].Load()
		if cum >= target {
			if i >= len(latencyBucketsNanos) {
				break
			}
			return float64(latencyBucketsNanos[i]) / 1e6
		}
	}
	// Fell into (or past) the overflow bucket: report the observed maximum.
	return float64(l.max.Load()) / 1e6
}

// Metrics is a registry of named counters and latency recorders. It is safe
// for concurrent use.
type Metrics struct {
	mu        sync.RWMutex
	counters  map[string]*atomic.Int64
	latencies map[string]*Latency
}

// NewMetrics returns an empty registry.
func NewMetrics() *Metrics {
	return &Metrics{
		counters:  make(map[string]*atomic.Int64),
		latencies: make(map[string]*Latency),
	}
}

func (m *Metrics) counter(name string) *atomic.Int64 {
	m.mu.RLock()
	c := m.counters[name]
	m.mu.RUnlock()
	if c != nil {
		return c
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c = m.counters[name]; c == nil {
		c = new(atomic.Int64)
		m.counters[name] = c
	}
	return c
}

// Inc increments a counter by one.
func (m *Metrics) Inc(name string) { m.counter(name).Add(1) }

// Add increments a counter by n.
func (m *Metrics) Add(name string, n int64) { m.counter(name).Add(n) }

// Observe records a latency sample under name.
func (m *Metrics) Observe(name string, d time.Duration) {
	m.mu.RLock()
	l := m.latencies[name]
	m.mu.RUnlock()
	if l == nil {
		m.mu.Lock()
		if l = m.latencies[name]; l == nil {
			l = &Latency{}
			m.latencies[name] = l
		}
		m.mu.Unlock()
	}
	l.Observe(d)
}

// Snapshot is an immutable copy of the registry's current values.
type Snapshot struct {
	Counters  map[string]int64          `json:"counters"`
	Latencies map[string]LatencySummary `json:"latencies"`
}

// Snapshot returns the current values of every counter and latency recorder.
func (m *Metrics) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Snapshot{
		Counters:  make(map[string]int64, len(m.counters)),
		Latencies: make(map[string]LatencySummary, len(m.latencies)),
	}
	for k, v := range m.counters {
		s.Counters[k] = v.Load()
	}
	for k, v := range m.latencies {
		s.Latencies[k] = v.summary()
	}
	return s
}
