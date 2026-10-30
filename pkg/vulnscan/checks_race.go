package vulnscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// checkRaceCondition probes for TOCTOU (Time-of-Check-Time-of-Use) race conditions
// in form submissions by sending N identical requests concurrently and analyzing
// diverging response codes or bodies.
//
// High-risk endpoints: coupon redemption, referral bonuses, vote/like endpoints,
// one-time-use token consumption, withdrawal/transfer initiation.
//
// Detection heuristics:
//  1. All N responses are identical → no race (baseline).
//  2. Majority succeed but ≥1 response differs (e.g. 200 vs 409) → probable race.
//  3. N * concurrent 200 responses on a "use-once" path → confirmed race.
func (s *Scanner) checkRaceCondition(form Form) []Vulnerability {
	var list []Vulnerability

	// Only probe likely sensitive endpoints
	if !isRaceConditionCandidate(form) {
		return list
	}

	const racerCount = 10
	const raceTimeout = 8 * time.Second

	type result struct {
		statusCode int
		bodyPrefix string // First 256 chars to detect diverging responses
		err        error
	}

	results := make([]result, racerCount)
	var wg sync.WaitGroup

	// Build a shared baseline payload
	vals := url.Values{}
	for _, inp := range form.Inputs {
		vals.Set(inp, "1") // Minimal value; sufficient to trigger backend logic
	}

	// Prepare all requests before firing to tighten timing window
	reqs := make([]*http.Request, racerCount)
	for i := 0; i < racerCount; i++ {
		var req *http.Request
		if form.Method == "POST" {
			req, _ = http.NewRequest("POST", form.Action, strings.NewReader(vals.Encode()))
			if req != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		} else {
			u, err := url.Parse(form.Action)
			if err != nil {
				continue
			}
			u.RawQuery = vals.Encode()
			req, _ = http.NewRequest("GET", u.String(), nil)
		}
		if req != nil {
			req.Header.Set("User-Agent", s.Config.UserAgent)
		}
		reqs[i] = req
	}

	// Use a start gate to fire all goroutines as simultaneously as possible
	startGate := make(chan struct{})

	for i := 0; i < racerCount; i++ {
		if reqs[i] == nil {
			continue
		}
		wg.Add(1)
		go func(idx int, req *http.Request) {
			defer wg.Done()
			<-startGate // Wait until all goroutines are spawned

			// Clone the request to avoid data race — http.Client.Do mutates *http.Request
			req = req.Clone(context.Background())

			client := &http.Client{
				Timeout: raceTimeout,
				CheckRedirect: func(r *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			prefix := string(bodyBytes)
			results[idx] = result{statusCode: resp.StatusCode, bodyPrefix: prefix}
		}(i, reqs[i])
	}

	// Fire all goroutines simultaneously
	close(startGate)
	wg.Wait()

	// Analyze results
	statusCodes := make(map[int]int)
	bodyPrefixes := make(map[string]int)

	for _, r := range results {
		if r.err != nil {
			continue
		}
		statusCodes[r.statusCode]++
		// Normalize body prefix: trim whitespace for comparison
		bodyPrefixes[strings.TrimSpace(r.bodyPrefix)]++
	}

	if len(statusCodes) <= 1 && len(bodyPrefixes) <= 1 {
		// Uniform responses — no observable race
		return list
	}

	// Build evidence string
	var codeSummary []string
	for code, count := range statusCodes {
		codeSummary = append(codeSummary, fmt.Sprintf("HTTP %d x%d", code, count))
	}
	evidenceStr := strings.Join(codeSummary, ", ")

	// Determine severity:
	// - Multiple 200s on a one-use endpoint → Critical
	// - Mixed 200/4xx → High (partial success, race likely exploitable)
	sev := SeverityHigh
	if statusCodes[200] > 1 && (statusCodes[409] > 0 || statusCodes[429] > 0 || statusCodes[400] > 0) {
		sev = SeverityCritical
	}

	list = append(list, Vulnerability{
		ID:          "WS-RACE-001",
		Name:        "Race Condition / TOCTOU",
		Description: fmt.Sprintf("Concurrent identical requests to '%s' produced diverging responses (%s). This indicates a TOCTOU race condition. On high-risk endpoints (coupon codes, transfers, one-time tokens) this can be exploited to redeem items multiple times.", form.Action, evidenceStr),
		Severity:    sev,
		URL:         form.Action,
		Payload:     fmt.Sprintf("%d concurrent %s requests", racerCount, form.Method),
		Evidence:    evidenceStr,
		Mitigation:  "Implement database-level idempotency (e.g. unique constraint + INSERT-then-check), use pessimistic locking or atomic compare-and-swap operations for critical resource transitions.",
	})

	return list
}

// isRaceConditionCandidate returns true when the form action URL looks like a
// sensitive endpoint worth probing for race conditions.
func isRaceConditionCandidate(form Form) bool {
	actionLower := strings.ToLower(form.Action)
	raceKeywords := []string{
		"coupon", "promo", "redeem", "discount", "voucher",
		"vote", "like", "upvote", "claim",
		"transfer", "withdraw", "payment", "checkout", "purchase", "buy",
		"referral", "bonus", "reward",
		"token", "otp", "verify", "confirm",
		"register", "signup", "subscribe",
	}
	for _, kw := range raceKeywords {
		if strings.Contains(actionLower, kw) {
			return true
		}
	}
	// Also probe if the form has inputs with suspicious names
	for _, inp := range form.Inputs {
		inpLower := strings.ToLower(inp)
		for _, kw := range raceKeywords {
			if strings.Contains(inpLower, kw) {
				return true
			}
		}
	}
	return false
}
