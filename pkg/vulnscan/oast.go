package vulnscan

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/dns"
	"mega-analyzer/pkg/logger"
)

// OASTServer manages out-of-band interactions
type OASTServer struct {
	Config  ScannerConfig
	Hits    []string
	DNSSrv  *dns.Server
	HTTPSrv *http.Server
	mu      sync.RWMutex

	// issued tracks interaction tokens handed out via IssueToken. A hit only
	// counts as confirmed when it carries a token the scanner actually
	// embedded in a payload — this prevents attributing unrelated traffic
	// (scanners, crawlers, retries) to the wrong form/parameter.
	issued map[string]struct{}
}

func NewOASTServer(cfg ScannerConfig) *OASTServer {
	return &OASTServer{
		Config: cfg,
		issued: make(map[string]struct{}),
	}
}

// IssueToken generates a unique interaction token for one payload. The token
// is registered so later hits carrying it can be attributed back to the
// payload that embedded it. 16 hex chars (64 bit) is collision-safe for a
// single scan's payload count.
func (o *OASTServer) IssueToken() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failure is unrecoverable for attribution; fall back to
		// a counter-based marker that is still registered for matching.
		o.mu.Lock()
		tok := fmt.Sprintf("tok-%d", len(o.issued))
		o.issued[tok] = struct{}{}
		o.mu.Unlock()
		return tok
	}
	tok := hex.EncodeToString(buf[:])
	o.mu.Lock()
	o.issued[tok] = struct{}{}
	o.mu.Unlock()
	return tok
}

// hitContainsKnownToken reports whether an interaction string carries any
// issued token (hex tokens and their dotted DNS-label encoding).
func (o *OASTServer) hitContainsKnownToken(hit string) (string, bool) {
	lower := strings.ToLower(hit)
	o.mu.RLock()
	defer o.mu.RUnlock()
	for tok := range o.issued {
		if strings.Contains(lower, tok) || strings.Contains(lower, dnsLabelForm(tok)) {
			return tok, true
		}
	}
	return "", false
}

// HasTokenHit reports whether any recorded interaction carries the given
// token, and returns the matching interaction string.
func (o *OASTServer) HasTokenHit(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	lowerTok := strings.ToLower(token)
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, hit := range o.Hits {
		lower := strings.ToLower(hit)
		if strings.Contains(lower, lowerTok) || strings.Contains(lower, dnsLabelForm(lowerTok)) {
			return hit, true
		}
	}
	return "", false
}

// dnsLabelForm encodes a token the way DNS name labels would carry it:
// chunks of at most 63 chars joined by dots. For 16-char tokens this is the
// identity, but the helper keeps the matcher correct if token lengths grow.
func dnsLabelForm(tok string) string {
	if len(tok) <= 63 {
		return tok
	}
	var parts []string
	for len(tok) > 0 {
		n := 63
		if len(tok) < n {
			n = len(tok)
		}
		parts = append(parts, tok[:n])
		tok = tok[n:]
	}
	return strings.Join(parts, ".")
}

func (o *OASTServer) Start() error {
	if !o.Config.LabMode {
		return nil // Only run in Lab Mode
	}

	logger.Info("Starting OAST Server (Lab Mode)")

	// Start DNS Server
	dns.HandleFunc(".", o.handleDNSRequest)
	o.DNSSrv = &dns.Server{Addr: o.Config.OASTBindAddrDNS, Net: "udp"}
	go func() {
		if err := o.DNSSrv.ListenAndServe(); err != nil {
			logger.Error("OAST DNS Server error", "err", err)
		}
	}()

	// Start HTTP Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", o.handleHTTPRequest)
	o.HTTPSrv = &http.Server{
		Addr:    o.Config.OASTBindAddrHTTP,
		Handler: mux,
	}
	go func() {
		if err := o.HTTPSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("OAST HTTP Server error", "err", err)
		}
	}()

	return nil
}

func (o *OASTServer) Stop() {
	if o.DNSSrv != nil {
		o.DNSSrv.Shutdown()
	}
	if o.HTTPSrv != nil {
		o.HTTPSrv.Close()
	}
}

func (o *OASTServer) AddHit(hit string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Hits = append(o.Hits, hit)
}

func (o *OASTServer) GetHits() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()

	hitsCopy := make([]string, len(o.Hits))
	copy(hitsCopy, o.Hits)
	return hitsCopy
}

func (o *OASTServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range m.Question {
			domain := strings.ToLower(q.Name)
			hit := fmt.Sprintf("DNS: %s", domain)
			if tok, known := o.hitContainsKnownToken(hit); known {
				logger.Info("OAST DNS Hit", "domain", domain, "token", tok)
			} else {
				logger.Info("OAST DNS Hit (no known token)", "domain", domain)
			}
			o.AddHit(hit)

			rr, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", q.Name))
			m.Answer = append(m.Answer, rr)
		}
	}
	w.WriteMsg(m)
}

func (o *OASTServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	hit := fmt.Sprintf("HTTP: %s", r.URL.Path)
	if tok, known := o.hitContainsKnownToken(hit); known {
		logger.Info("OAST HTTP Hit", "method", r.Method, "path", r.URL.Path, "token", tok)
	} else {
		logger.Info("OAST HTTP Hit (no known token)", "method", r.Method, "path", r.URL.Path)
	}
	o.AddHit(hit)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OAST Server Acknowledged"))
}
