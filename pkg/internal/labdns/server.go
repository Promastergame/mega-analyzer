package labdns

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/dns"
)

// DNSServer is the interface for a session-scoped DNS interceptor.
type DNSServer interface {
	Start(ctx context.Context) error
	Stop() error
	Addr() string
	QueryLog() []DNSQueryRecord
	Stats() DNSStats
}

// Config holds the Lab DNS server parameters.
type Config struct {
	ListenAddr string // e.g. "127.0.0.1:15353"
	Upstream   string // optional; empty means offline/refuse non-sinkholed queries
	Rules      *SinkholeRules
	SinkIP     string // Custom default sinkhole IP
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("missing listen address")
	}
	return nil
}

// LabDNS is a local intercepting DNS server that logs all queries,
// applies sinkhole rules, and proxies the rest upstream.
type LabDNS struct {
	cfg      *Config
	rules    *SinkholeRules
	log      *queryLog
	udpSrv   *dns.Server
	tcpSrv   *dns.Server
	client   *dns.Client
	started  bool
	mu       sync.Mutex
	stopOnce sync.Once
}

// NewDNSServer creates a new Lab DNS server.
func NewDNSServer(cfg *Config) *LabDNS {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:15353"
	}
	if cfg.Rules == nil {
		cfg.Rules = NewSinkholeRules(false, nil)
	}
	if cfg.SinkIP != "" {
		cfg.Rules.SetSinkIP(cfg.SinkIP)
	}
	return &LabDNS{
		cfg:   cfg,
		rules: cfg.Rules,
		log:   newQueryLog(),
		client: &dns.Client{
			Net:     "udp",
			Timeout: 5 * time.Second,
		},
	}
}

// Start binds UDP and TCP listeners and begins serving.
// It blocks until the context is cancelled or Stop is called.
func (s *LabDNS) Start(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("labdns: resolve udp addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("labdns: listen udp %s: %w", s.cfg.ListenAddr, err)
	}

	tcpListener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("labdns: listen tcp %s: %w", s.cfg.ListenAddr, err)
	}

	s.mu.Lock()
	s.udpSrv = &dns.Server{
		PacketConn: udpConn,
		Handler:    mux,
	}
	s.tcpSrv = &dns.Server{
		Listener: tcpListener,
		Handler:  mux,
	}
	s.started = true
	s.mu.Unlock()

	errCh := make(chan error, 2)
	go func() { errCh <- s.udpSrv.ActivateAndServe() }()
	go func() { errCh <- s.tcpSrv.ActivateAndServe() }()

	select {
	case <-ctx.Done():
		s.Stop()
		return ctx.Err()
	case err := <-errCh:
		s.Stop()
		return err
	}
}

// StartBackground starts the DNS server in the background and returns
// once both UDP and TCP listeners are ready.
func (s *LabDNS) StartBackground() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("labdns: resolve udp addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("labdns: listen udp %s: %w", s.cfg.ListenAddr, err)
	}

	tcpListener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("labdns: listen tcp %s: %w", s.cfg.ListenAddr, err)
	}

	s.mu.Lock()
	s.udpSrv = &dns.Server{
		PacketConn: udpConn,
		Handler:    mux,
	}
	s.tcpSrv = &dns.Server{
		Listener: tcpListener,
		Handler:  mux,
	}
	s.started = true
	s.mu.Unlock()

	go func() { _ = s.udpSrv.ActivateAndServe() }()
	go func() { _ = s.tcpSrv.ActivateAndServe() }()

	return nil
}

// Stop shuts down UDP and TCP listeners.
func (s *LabDNS) Stop() error {
	var firstErr error
	s.stopOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.udpSrv != nil {
			if err := s.udpSrv.Shutdown(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if s.tcpSrv != nil {
			if err := s.tcpSrv.Shutdown(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		s.started = false
	})
	return firstErr
}

// Addr returns the configured listen address.
func (s *LabDNS) Addr() string {
	return s.cfg.ListenAddr
}

// QueryLog returns a snapshot of all DNS queries observed so far.
func (s *LabDNS) QueryLog() []DNSQueryRecord {
	return s.log.Snapshot()
}

// ClearLog clears the recorded queries.
func (s *LabDNS) ClearLog() {
	s.log.mu.Lock()
	s.log.records = nil
	s.log.mu.Unlock()
}

// IsRunning returns true if the server is currently serving requests.
func (s *LabDNS) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// AddBlockRule adds a new domain pattern to the block list.
func (s *LabDNS) AddBlockRule(pattern string) {
	s.rules.AddRule(SinkholeRuleConfig{
		Pattern: pattern,
		Name:    "manual-block",
	})
}

// GetBlockRules returns the currently active block rules.
func (s *LabDNS) GetBlockRules() []string {
	s.rules.mu.RLock()
	defer s.rules.mu.RUnlock()

	var rules []string
	for p := range s.rules.exact {
		rules = append(rules, p)
	}
	for _, w := range s.rules.wildcards {
		rules = append(rules, "*"+w.suffix)
	}
	return rules
}

// Stats computes aggregate statistics over the recorded queries.
func (s *LabDNS) Stats() DNSStats {
	records := s.log.Snapshot()
	stats := DNSStats{TotalQueries: len(records)}

	nameCount := make(map[string]int, len(records))
	sinkedSet := make(map[string]struct{})

	for _, r := range records {
		nameCount[r.QueryName]++
		switch r.Action {
		case "forwarded":
			stats.ForwardedCount++
		case "sinked":
			stats.SinkholeCount++
			sinkedSet[r.QueryName] = struct{}{}
		case "blocked":
			stats.BlockedCount++
		case "nxdomain":
			stats.NXDomainCount++
		}
		if r.Error != "" {
			stats.ErrorCount++
		}
	}

	stats.UniqueNames = len(nameCount)
	stats.BlockedQueries = stats.BlockedCount

	// Top domains.
	type kv struct {
		name  string
		count int
	}
	sorted := make([]kv, 0, len(nameCount))
	for k, v := range nameCount {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count == sorted[j].count {
			return sorted[i].name < sorted[j].name
		}
		return sorted[i].count > sorted[j].count
	})
	limit := 20
	if len(sorted) < limit {
		limit = len(sorted)
	}
	stats.TopDomains = make([]DomainCount, limit)
	for i := 0; i < limit; i++ {
		stats.TopDomains[i] = DomainCount{Name: sorted[i].name, Count: sorted[i].count}
	}

	// Sinkholed names.
	stats.SinkholedNames = make([]string, 0, len(sinkedSet))
	for name := range sinkedSet {
		stats.SinkholedNames = append(stats.SinkholedNames, name)
	}
	sort.Strings(stats.SinkholedNames)

	// C2 candidates: domains queried infrequently with unusual length / entropy.
	for name, count := range nameCount {
		if _, sinked := sinkedSet[name]; sinked {
			continue
		}
		if count <= 2 && looksLikeC2(name) {
			stats.C2Candidates = append(stats.C2Candidates, name)
		}
	}
	sort.Strings(stats.C2Candidates)

	return stats
}

// handleQuery is the core DNS handler.
func (s *LabDNS) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()

	record := DNSQueryRecord{
		Timestamp:  start.UTC(),
		SourceAddr: w.RemoteAddr().String(),
	}

	if len(req.Question) == 0 {
		record.Action = "blocked"
		record.Error = "empty question"
		s.log.Append(record)
		refuse(w, req)
		return
	}

	q := req.Question[0]
	record.QueryName = strings.TrimSuffix(strings.ToLower(q.Name), ".")
	record.QueryType = dns.TypeToString[q.Qtype]

	m := s.rules.Match(record.QueryName)
	if m.Matched {
		record.Action = "sinked"
		record.AnswerIP = m.Target
		record.RuleName = m.RuleName
		record.LatencyMs = time.Since(start).Milliseconds()
		s.log.Append(record)

		s.respondSinkhole(w, req, q, m.Target)
		return
	}

	// Forward to upstream only when explicitly configured. Default is offline.
	if strings.TrimSpace(s.cfg.Upstream) == "" {
		record.Action = "blocked"
		record.Error = "offline mode: no upstream DNS configured"
		record.LatencyMs = time.Since(start).Milliseconds()
		s.log.Append(record)
		refuse(w, req)
		return
	}
	record.Upstream = s.cfg.Upstream
	resp, rtt, err := s.client.Exchange(req, s.cfg.Upstream)
	record.LatencyMs = rtt.Milliseconds()
	if record.LatencyMs == 0 {
		record.LatencyMs = time.Since(start).Milliseconds()
	}

	if err != nil {
		record.Action = "forwarded"
		record.Error = err.Error()
		s.log.Append(record)
		refuse(w, req)
		return
	}

	if resp.Rcode == dns.RcodeNameError {
		record.Action = "nxdomain"
	} else {
		record.Action = "forwarded"
	}

	// Extract first A/AAAA answer for logging.
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			record.AnswerIP = v.A.String()
			record.Answer = v.String()
		case *dns.AAAA:
			if record.AnswerIP == "" {
				record.AnswerIP = v.AAAA.String()
				record.Answer = v.String()
			}
		case *dns.CNAME:
			if record.Answer == "" {
				record.Answer = v.Target
			}
		}
	}

	s.log.Append(record)
	_ = w.WriteMsg(resp)
}

// respondSinkhole crafts a synthetic A-record response pointing to the sinkhole IP.
func (s *LabDNS) respondSinkhole(w dns.ResponseWriter, req *dns.Msg, q dns.Question, sinkIP string) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	ip := net.ParseIP(sinkIP)
	if ip == nil {
		ip = net.ParseIP(DefaultSinkholeIP)
	}

	switch q.Qtype {
	case dns.TypeA:
		if ip4 := ip.To4(); ip4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip4,
			})
		}
	case dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: ip,
		})
	default:
		// For unsupported types under sinkhole, return NOERROR with no answers.
	}

	_ = w.WriteMsg(resp)
}

func refuse(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeRefused)
	_ = w.WriteMsg(resp)
}

// looksLikeC2 heuristically checks if a domain name looks like a
// dynamically generated C2 domain (DGA).
func looksLikeC2(name string) bool {
	// Strip TLD.
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return false
	}
	label := parts[0]
	if len(parts) > 2 {
		// Use the second-level domain for analysis.
		label = parts[len(parts)-2]
	}

	if len(label) < 8 {
		return false
	}

	// Calculate Shannon Entropy
	frequencies := make(map[rune]int)
	for _, r := range label {
		frequencies[r]++
	}
	var entropy float64
	for _, count := range frequencies {
		p := float64(count) / float64(len(label))
		entropy -= p * math.Log2(p)
	}

	// High consonant ratio is suspicious.
	consonants := 0
	digits := 0
	for _, r := range label {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case !isVowel(r) && r >= 'a' && r <= 'z':
			consonants++
		}
	}

	total := len(label)
	if total == 0 {
		return false
	}

	consonantRatio := float64(consonants) / float64(total)
	digitRatio := float64(digits) / float64(total)

	// Identify highly suspicious patterns:
	// 1. High Shannon Entropy (> 3.9 is typical for randomized text) with high consonant ratio
	// 2. High overall Shannon Entropy (> 4.2)
	if entropy > 3.9 && consonantRatio > 0.6 {
		return true
	}
	if entropy > 4.2 {
		return true
	}

	// Legacy fallback: Either very consonant-heavy or digit-heavy suggests DGA.
	return consonantRatio > 0.65 || digitRatio > 0.4 || (consonantRatio > 0.5 && digitRatio > 0.2)
}

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}
