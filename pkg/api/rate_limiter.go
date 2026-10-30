package api

import (
	"container/list"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TOKEN BUCKET RATE LIMITER — per-IP with LRU eviction
// ═══════════════════════════════════════════════════════════════════════════════

type ipRateLimiter struct {
	ips    map[string]*ipEntry
	mu     sync.Mutex
	maxIPs int        // hard cap on tracked IPs to prevent memory exhaustion
	order  *list.List // LRU eviction order (*list.Element.Value = ip string)
}

type ipEntry struct {
	bucket  *tokenBucket
	element *list.Element
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

const (
	defaultMaxTrackedIPs = 20000           // 20k unique IPs ~ 2.5 MB
	desyncIPNet          = "100.64.0.0/10" // carrier-grade NAT — often used for desync
)

var limiter = &ipRateLimiter{
	ips:    make(map[string]*ipEntry),
	maxIPs: defaultMaxTrackedIPs,
	order:  list.New(),
}

// janitorOnce lazily starts the stale-entry cleanup goroutine the first
// time the limiter actually sees traffic, so binaries importing pkg/api for
// other uses don't carry an init()-time cleanup loop. The janitor lives as
// long as the serving process.
var janitorOnce sync.Once

func startRateLimiterJanitor() {
	janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				limiter.evictStale()
			}
		}()
	})
}

// evictStale drops IP entries not seen for over an hour.
func (l *ipRateLimiter) evictStale() {
	l.mu.Lock()
	now := time.Now()
	var next *list.Element
	for e := l.order.Front(); e != nil; e = next {
		next = e.Next()
		ip := e.Value.(string)
		entry, ok := l.ips[ip]
		if ok && now.Sub(entry.bucket.lastRefill) > 1*time.Hour {
			delete(l.ips, ip)
			l.order.Remove(e)
		}
	}
	l.mu.Unlock()
}

// evictOldestLocked removes the least recently seen IP (must hold limiter.mu).
func (l *ipRateLimiter) evictOldestLocked() {
	front := l.order.Front()
	if front == nil {
		return
	}
	ip := front.Value.(string)
	delete(l.ips, ip)
	l.order.Remove(front)
}

func (l *ipRateLimiter) allow(ip string, rate float64, capacity float64) (bool, float64, time.Time) {
	startRateLimiterJanitor()
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, exists := l.ips[ip]
	var bucket *tokenBucket
	if !exists {
		// Evict oldest if at capacity before inserting new IP
		if len(l.ips) >= l.maxIPs {
			l.evictOldestLocked()
		}
		bucket = &tokenBucket{
			tokens:     capacity,
			lastRefill: now,
		}
		elem := l.order.PushBack(ip) // O(1)
		l.ips[ip] = &ipEntry{bucket: bucket, element: elem}
	} else {
		bucket = entry.bucket
		l.order.MoveToBack(entry.element) // O(1) instead of O(n) scan
	}

	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens = bucket.tokens + elapsed*rate
	if bucket.tokens > capacity {
		bucket.tokens = capacity
	}
	bucket.lastRefill = now

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true, bucket.tokens, now
	}
	return false, bucket.tokens, now
}

// clientIP extracts the rate-limit key. By default the direct peer address
// is used; with MEGA_ANALYZER_TRUST_PROXY=1 the X-Forwarded-For header is
// trusted so clients behind a reverse proxy do not share a single bucket.
func (s *APIServer) clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	if s.getTrustProxy() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if first != "" {
				ip = first
			}
		}
	}
	return ip
}

func (s *APIServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only limit API requests to keep UI assets accessible
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// Extract client IP address
		ip := s.clientIP(r)

		// Default: 100 burst, 5 refill/sec
		limit := 100.0
		refillRate := 5.0

		// Heavier rate limiting for expensive endpoints (scan, apk, test)
		if strings.Contains(r.URL.Path, "/scan/") ||
			strings.Contains(r.URL.Path, "/rules/test") {
			limit = 20.0
			refillRate = 1.0 // 1 req/sec for heavy ops
		}

		allowed, remaining, _ := limiter.allow(ip, refillRate, limit)

		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.0f", limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%.0f", remaining))

		resetTime := time.Now().Add(time.Second * time.Duration((limit-remaining)/refillRate))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

		if !allowed {
			incRateLimitReject()
			writeProblem(
				w, r,
				http.StatusTooManyRequests,
				"ERR_RATE_LIMIT_EXCEEDED",
				"Too Many Requests",
				"API requests frequency limits exceeded. Please throttle client scripts.",
				"Slow down rule creation, wait for current requests to finish, or implement backing off algorithms.",
				nil,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}
