package labkit

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Middleware wraps an http.Handler with extra behaviour.
type Middleware func(http.Handler) http.Handler

// chain applies middlewares so that the first listed is the outermost wrapper
// (i.e. it runs first on the way in and last on the way out).
func chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// statusRecorder captures the response status and byte count while remaining a
// transparent http.ResponseWriter. It forwards Hijack so scenario-driven
// connection drops and the WebSocket upgrade keep working.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

// Hijack exposes the underlying connection when the server supports it.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

// recovery converts a panic in a downstream handler into a 500 rather than
// tearing down the server.
func recovery(log *Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					log.Error("handler panic", Fields{"path": r.URL.Path, "panic": fmt.Sprint(v)})
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// requestLogger records structured access logs and per-request metrics.
func requestLogger(log *Logger, m *Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			m.Inc("http.requests")
			next.ServeHTTP(rec, r)
			dur := time.Since(start)
			m.Observe("http.latency", dur)
			m.Inc(fmt.Sprintf("http.status.%d", rec.status))
			log.Info("request", Fields{
				"method":   r.Method,
				"path":     r.URL.Path,
				"status":   rec.status,
				"bytes":    rec.written,
				"duration": dur.String(),
				"remote":   r.RemoteAddr,
			})
		})
	}
}

// scenarioMiddleware injects latency and faults from the configured Scenario.
// A FaultTimeout stalls for the rolled latency and then drops the connection
// (via hijack) to emulate an upstream that never answers; if the connection
// cannot be hijacked it falls back to a 504.
func scenarioMiddleware(s *Scenario, m *Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			out := s.Roll()
			if out.Latency > 0 {
				select {
				case <-time.After(out.Latency):
				case <-r.Context().Done():
					return
				}
			}
			switch out.Fault {
			case FaultError:
				m.Inc("scenario.injected_error")
				http.Error(w, "injected error", out.Status)
				return
			case FaultTimeout:
				m.Inc("scenario.injected_timeout")
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						_ = conn.Close()
						return
					}
				}
				http.Error(w, "injected timeout", http.StatusGatewayTimeout)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
