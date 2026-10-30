// Package trackercollector is a tiny local sink that stands in for "the
// server a spyware/backdoor beacon phones home to". It never leaves
// 127.0.0.1, does nothing with what it receives besides log it, and exists
// purely so labs/servers tests can assert whether a beacon reached it.
package trackercollector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Hit is one recorded beacon/tracking request.
type Hit struct {
	Timestamp  time.Time         `json:"timestamp"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	RemoteAddr string            `json:"remote_addr"`
	BodySHA256 string            `json:"body_sha256"`
	BodyLen    int               `json:"body_len"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// maxHits bounds the in-memory ring buffer so a long-running lab session
// can't grow this without limit.
const maxHits = 2000

// interestingHeaders are copied into each Hit for inspection; the collector
// never needs the full header set.
var interestingHeaders = []string{"User-Agent", "X-Beacon-Source", "X-Session-Token", "Content-Type"}

// Server is a minimal HTTP sink recording every request it receives.
type Server struct {
	mu   sync.Mutex
	hits []Hit
	srv  *http.Server
	ln   net.Listener
}

// New creates a Server; it does not start listening yet.
func New() *Server {
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/_hits", s.handleHits)
	mux.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", s.handleBeacon)
	s.srv = &http.Server{Handler: mux}
	return s
}

// StartBackground binds addr (use "127.0.0.1:0" for an ephemeral port) and
// begins serving in a background goroutine. Call Addr() afterwards for the
// actual bound address.
func (s *Server) StartBackground(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Addr returns the address this server is actually bound to.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Stop shuts the server down.
func (s *Server) Stop() error {
	if s.ln == nil {
		return nil
	}
	return s.srv.Close()
}

// Hits returns a snapshot of every request recorded so far.
func (s *Server) Hits() []Hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Hit, len(s.hits))
	copy(out, s.hits)
	return out
}

// Clear wipes the recorded hit log.
func (s *Server) Clear() {
	s.mu.Lock()
	s.hits = nil
	s.mu.Unlock()
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	sum := sha256.Sum256(body)

	hdrs := make(map[string]string)
	for _, h := range interestingHeaders {
		if v := r.Header.Get(h); v != "" {
			hdrs[h] = v
		}
	}

	hit := Hit{
		Timestamp:  time.Now().UTC(),
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		BodySHA256: hex.EncodeToString(sum[:]),
		BodyLen:    len(body),
		Headers:    hdrs,
	}

	s.mu.Lock()
	s.hits = append(s.hits, hit)
	if len(s.hits) > maxHits {
		s.hits = s.hits[len(s.hits)-maxHits:]
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Hits())
}
