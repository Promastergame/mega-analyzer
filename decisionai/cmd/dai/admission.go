package main

import "net/http"

// Bound active expensive requests instead of growing an unbounded inference
// queue. This is a concurrency limit, not an OS memory or CPU guarantee.
func limitInference(next http.Handler, maximum int) http.Handler {
	if maximum < 1 {
		maximum = 1
	}
	slots := make(chan struct{}, maximum)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/decide", "/v1/see", "/v1/game":
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"inference capacity reached; retry later"}`))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
