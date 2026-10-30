package labdns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/dns"
)

// ── Sinkhole Rules Tests ─────────────────────────────────────

func TestSinkholeRulesExactMatch(t *testing.T) {
	rules := NewSinkholeRules(false, []SinkholeRuleConfig{
		{Pattern: "evil.com", Target: "10.0.0.1", Name: "evil"},
		{Pattern: "tracker.io"},
	})

	tests := []struct {
		query   string
		matched bool
		target  string
		rule    string
	}{
		{"evil.com", true, "10.0.0.1", "evil"},
		{"EVIL.COM", true, "10.0.0.1", "evil"},
		{"evil.com.", true, "10.0.0.1", "evil"},
		{"tracker.io", true, DefaultSinkholeIP, ""},
		{"good.com", false, "", ""},
		{"sub.evil.com", false, "", ""},
	}
	for _, tt := range tests {
		m := rules.Match(tt.query)
		if m.Matched != tt.matched {
			t.Errorf("Match(%q) matched = %v, want %v", tt.query, m.Matched, tt.matched)
		}
		if m.Target != tt.target {
			t.Errorf("Match(%q) target = %q, want %q", tt.query, m.Target, tt.target)
		}
		if m.RuleName != tt.rule {
			t.Errorf("Match(%q) rule = %q, want %q", tt.query, m.RuleName, tt.rule)
		}
	}
}

func TestSinkholeRulesCustomSinkIP(t *testing.T) {
	rules := NewSinkholeRules(false, []SinkholeRuleConfig{
		{Pattern: "custom.com"},
	})
	rules.SetSinkIP("192.168.1.99")
	m := rules.Match("custom.com")
	if !m.Matched {
		t.Fatal("expected match")
	}
	if m.Target != "192.168.1.99" {
		t.Errorf("expected target 192.168.1.99, got %q", m.Target)
	}
}

func TestSinkholeRulesWildcard(t *testing.T) {
	rules := NewSinkholeRules(false, []SinkholeRuleConfig{
		{Pattern: "*.tracker.io", Name: "tracker-wc"},
		{Pattern: "*.evil.com", Target: "10.0.0.2", Name: "evil-wc"},
	})

	tests := []struct {
		query   string
		matched bool
		target  string
	}{
		{"sub.tracker.io", true, DefaultSinkholeIP},
		{"deep.sub.tracker.io", true, DefaultSinkholeIP},
		{"tracker.io", true, DefaultSinkholeIP}, // bare domain also matches wildcard
		{"sub.evil.com", true, "10.0.0.2"},
		{"good.com", false, ""},
	}
	for _, tt := range tests {
		m := rules.Match(tt.query)
		if m.Matched != tt.matched {
			t.Errorf("Match(%q) matched = %v, want %v", tt.query, m.Matched, tt.matched)
		}
		if m.Matched && m.Target != tt.target {
			t.Errorf("Match(%q) target = %q, want %q", tt.query, m.Target, tt.target)
		}
	}
}

func TestSinkholeRulesBlockAll(t *testing.T) {
	rules := NewSinkholeRules(true, nil)
	m := rules.Match("anything.com")
	if !m.Matched {
		t.Fatal("expected block-all to match everything")
	}
	if m.RuleName != "block-all" {
		t.Errorf("expected rule name 'block-all', got %q", m.RuleName)
	}
}

func TestSinkholeRulesSafetyNet(t *testing.T) {
	rules := NewSinkholeRulesWithSafetyNet(false, nil)
	for _, domain := range []string{
		"play.googleapis.com",
		"www.googleapis.com",
		"android.googleapis.com",
		"connectivitycheck.gstatic.com",
	} {
		m := rules.Match(domain)
		if !m.Matched {
			t.Errorf("SafetyNet rule should match %q", domain)
		}
	}
	m := rules.Match("example.com")
	if m.Matched {
		t.Error("SafetyNet rules should not match example.com")
	}
}

// ── Query Log Tests ──────────────────────────────────────────

func TestQueryLogConcurrency(t *testing.T) {
	l := newQueryLog()
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 100; j++ {
				l.Append(DNSQueryRecord{QueryName: "test.com"})
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	snap := l.Snapshot()
	if len(snap) != 1000 {
		t.Errorf("expected 1000 records, got %d", len(snap))
	}
}

// ── DNS Server Integration Tests ─────────────────────────────

func findFreePort(t *testing.T) string {
	t.Helper()

	// LabDNS binds UDP and TCP on the same port. On Windows a UDP-only free
	// port can still fall into a TCP excluded/reserved range, so choose a TCP
	// port first and verify UDP can bind to it too.
	for i := 0; i < 20; i++ {
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("find free tcp port: %v", err)
		}
		addr := tcpLn.Addr().String()
		_ = tcpLn.Close()

		udpLn, err := net.ListenPacket("udp", addr)
		if err == nil {
			_ = udpLn.Close()
			return addr
		}
	}
	t.Fatalf("could not find a port bindable by both TCP and UDP")
	return ""
}

func TestLabDNSSinkhole(t *testing.T) {
	addr := findFreePort(t)
	rules := NewSinkholeRules(false, []SinkholeRuleConfig{
		{Pattern: "evil.test", Target: "10.0.0.66", Name: "test-evil"},
	})

	srv := NewDNSServer(&Config{
		ListenAddr: addr,
		Upstream:   "8.8.8.8:53", // won't be used for sinked domains
		Rules:      rules,
	})

	if err := srv.StartBackground(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	// Allow listeners to bind.
	time.Sleep(50 * time.Millisecond)

	// Query a sinked domain.
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("evil.test"), dns.TypeA)

	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer for sinked domain")
	}

	aRecord, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if aRecord.A.String() != "10.0.0.66" {
		t.Errorf("expected sinkhole IP 10.0.0.66, got %s", aRecord.A.String())
	}

	// Query for TypeAAAA to cover respondSinkhole TypeAAAA branch
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(dns.Fqdn("evil.test"), dns.TypeAAAA)
	respAAAA, _, err := client.Exchange(msgAAAA, addr)
	if err == nil && len(respAAAA.Answer) > 0 {
		_, ok := respAAAA.Answer[0].(*dns.AAAA)
		if !ok {
			t.Errorf("expected AAAA record, got %T", respAAAA.Answer[0])
		}
	}

	// Add a wildcard rule to srv to test GetBlockRules wildcard coverage
	srv.AddBlockRule("*.wildcard.test")
	foundWildcard := false
	for _, rule := range srv.GetBlockRules() {
		if rule == "*.wildcard.test" {
			foundWildcard = true
			break
		}
	}
	if !foundWildcard {
		t.Error("Expected wildcard rule in GetBlockRules, not found")
	}

	// Check query log.
	log := srv.QueryLog()
	if len(log) < 1 {
		t.Fatalf("expected log entries, got %d", len(log))
	}
	if log[0].Action != "sinked" {
		t.Errorf("expected action 'sinked', got %q", log[0].Action)
	}
	if log[0].RuleName != "test-evil" {
		t.Errorf("expected rule 'test-evil', got %q", log[0].RuleName)
	}
}

func TestLabDNSBlockAll(t *testing.T) {
	addr := findFreePort(t)
	rules := NewSinkholeRules(true, nil)

	srv := NewDNSServer(&Config{
		ListenAddr: addr,
		Rules:      rules,
	})

	if err := srv.StartBackground(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("any-domain.com"), dns.TypeA)

	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("block-all should still return a sinkhole answer")
	}

	log := srv.QueryLog()
	if len(log) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(log))
	}
	if log[0].Action != "sinked" {
		t.Errorf("expected action 'sinked', got %q", log[0].Action)
	}
}

func TestLabDNSStats(t *testing.T) {
	addr := findFreePort(t)
	rules := NewSinkholeRules(false, []SinkholeRuleConfig{
		{Pattern: "sinked.test", Name: "test"},
	})

	srv := NewDNSServer(&Config{
		ListenAddr: addr,
		Rules:      rules,
	})

	if err := srv.StartBackground(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

	// Send sinked query.
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("sinked.test"), dns.TypeA)
	_, _, _ = client.Exchange(msg, addr)

	// Send another sinked query.
	_, _, _ = client.Exchange(msg, addr)

	time.Sleep(20 * time.Millisecond)

	stats := srv.Stats()
	if stats.TotalQueries != 2 {
		t.Errorf("expected 2 total queries, got %d", stats.TotalQueries)
	}
	if stats.SinkholeCount != 2 {
		t.Errorf("expected 2 sinkhole, got %d", stats.SinkholeCount)
	}
	if stats.UniqueNames != 1 {
		t.Errorf("expected 1 unique, got %d", stats.UniqueNames)
	}
}

func TestLabDNSStartAndStop(t *testing.T) {
	addr := findFreePort(t)
	srv := NewDNSServer(&Config{ListenAddr: addr})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := srv.Start(ctx)
	if err != nil && err != context.DeadlineExceeded {
		t.Fatalf("expected deadline exceeded or nil, got: %v", err)
	}
}

// ── C2 / DGA Heuristic Tests ─────────────────────────────────

func TestLooksLikeC2(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"google.com", false},
		{"facebook.com", false},
		{"xnrghtklm.xyz", true},                            // high consonant ratio
		{"38472937h2.info", true},                          // high digit ratio
		{"a.com", false},                                   // too short
		{"nodots", false},                                  // no dots, len(parts) < 2
		{"sub.google.com", false},                          // subdomain, len(parts) > 2
		{"abcdefghijklmnopqrstuvwxyz1234567890.com", true}, // high entropy > 4.2
		{"zxvtsrqpnmlkjhgfdcba9876.com", true},             // high entropy > 3.9 & consonant ratio > 0.6
	}
	for _, tt := range tests {
		got := looksLikeC2(tt.name)
		if got != tt.want {
			t.Errorf("looksLikeC2(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsVowel(t *testing.T) {
	vowels := "aeiou"
	for _, v := range vowels {
		if !isVowel(v) {
			t.Errorf("isVowel(%q) = false, want true", string(v))
		}
	}
	if isVowel('b') {
		t.Error("isVowel('b') should be false")
	}
}

func TestDNSQueryRecordFields(t *testing.T) {
	r := DNSQueryRecord{
		Timestamp: time.Now(),
		QueryName: "test.com",
		QueryType: "A",
		Action:    "forwarded",
	}
	if r.QueryName != "test.com" {
		t.Error("field not set")
	}
	if r.Timestamp.IsZero() {
		t.Error("Timestamp not set")
	}
	if r.Action != "forwarded" {
		t.Errorf("Action = %q, want %q", r.Action, "forwarded")
	}
	_ = strings.ToLower(r.QueryType) // ensure string ops work
}

type mockWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (m *mockWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	return nil
}

func (m *mockWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}

func TestMissingCoverageItems(t *testing.T) {
	// Test BlockAll and SetBlockAll
	rules := NewSinkholeRules(false, nil)
	if rules.BlockAll() {
		t.Error("Expected BlockAll to be false")
	}
	rules.SetBlockAll(true)
	if !rules.BlockAll() {
		t.Error("Expected BlockAll to be true after SetBlockAll(true)")
	}

	// Test Addr
	addr := findFreePort(t)
	srv := NewDNSServer(&Config{ListenAddr: addr})
	if srv.Addr() != addr {
		t.Errorf("Addr() = %q, want %q", srv.Addr(), addr)
	}

	// Test refuse directly
	mw := &mockWriter{}
	refuse(mw, new(dns.Msg))
	if mw.msg == nil || mw.msg.Rcode != dns.RcodeRefused {
		t.Errorf("refuse() did not set RcodeRefused")
	}

	// Test NewDNSServer config defaults
	srvNil := NewDNSServer(nil)
	if srvNil.Addr() != "127.0.0.1:15353" {
		t.Errorf("Expected default listen addr, got %s", srvNil.Addr())
	}
	srvEmpty := NewDNSServer(&Config{})
	if srvEmpty.Addr() != "127.0.0.1:15353" {
		t.Errorf("Expected default listen addr for empty config, got %s", srvEmpty.Addr())
	}

	// Test Start with invalid address to cover error branch
	srvInvalid := NewDNSServer(&Config{ListenAddr: "999.999.999.999:9999"})
	err := srvInvalid.Start(context.Background())
	if err == nil {
		t.Error("Expected error for invalid listen address, got nil")
	}

	srvInvalidBG := NewDNSServer(&Config{ListenAddr: "999.999.999.999:9999"})
	errBG := srvInvalidBG.StartBackground()
	if errBG == nil {
		t.Error("Expected error for invalid listen address in background, got nil")
	}

	// Test Start bind failure (TCP already bound)
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		defer tcpLn.Close()
		srvBindFail := NewDNSServer(&Config{ListenAddr: tcpLn.Addr().String()})
		// This should fail to bind TCP since tcpLn is holding it!
		errStart := srvBindFail.Start(context.Background())
		if errStart == nil {
			t.Error("Expected TCP bind failure, got nil")
		}

		// Test StartBackground with TCP already bound
		errBG2 := srvBindFail.StartBackground()
		if errBG2 == nil {
			t.Error("Expected TCP bind failure in background, got nil")
		}
	}
}

func TestLabDNSUpstreamForward(t *testing.T) {
	// 1. Launch a mock upstream DNS server
	upstreamAddr := findFreePort(t)
	upstreamMux := dns.NewServeMux()
	upstreamMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		q := req.Question[0]
		if q.Name == "good.test." {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.168.1.100").To4(),
			})
		} else {
			resp.SetRcode(req, dns.RcodeNameError) // NXDOMAIN
		}
		_ = w.WriteMsg(resp)
	})

	upstreamSrv := &dns.Server{
		Addr:    upstreamAddr,
		Net:     "udp",
		Handler: upstreamMux,
	}
	go func() { _ = upstreamSrv.ListenAndServe() }()
	defer upstreamSrv.Shutdown()

	time.Sleep(50 * time.Millisecond) // Allow upstream to start

	// 2. Launch our LabDNS server with upstream configured to the mock upstream
	addr := findFreePort(t)
	srv := NewDNSServer(&Config{
		ListenAddr: addr,
		Upstream:   upstreamAddr,
	})
	if err := srv.StartBackground(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	// 3. Query our LabDNS server for a domain that should be forwarded successfully
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("good.test"), dns.TypeA)

	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected answer from forwarded query")
	}
	aRecord, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if aRecord.A.String() != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", aRecord.A.String())
	}

	// 4. Query for a domain that returns NXDOMAIN to cover the NXDOMAIN branch
	msgNX := new(dns.Msg)
	msgNX.SetQuestion(dns.Fqdn("nonexistent.test"), dns.TypeA)
	respNX, _, err := client.Exchange(msgNX, addr)
	if err != nil {
		t.Fatalf("exchange NX: %v", err)
	}
	if respNX.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN (Rcode 3), got %d", respNX.Rcode)
	}

	// Verify stats
	stats := srv.Stats()
	if stats.TotalQueries < 2 {
		t.Errorf("expected at least 2 total queries in stats, got %d", stats.TotalQueries)
	}
}
