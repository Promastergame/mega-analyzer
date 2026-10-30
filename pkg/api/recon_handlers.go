package api

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PORT SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

type PortResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

var commonPortServices = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
	631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
	1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper", 3306: "MySQL", 3389: "RDP",
	4369: "RabbitMQ-EPMD", 5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
	5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM",
	9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
	10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Shard",
	50070: "Hadoop-HDFS", 61616: "ActiveMQ",
}

func firstSafeResolvedIP(host string) (string, error) {
	clean := strings.Trim(strings.TrimSuffix(strings.ToLower(host), "."), "[]")
	if clean == "" {
		return "", fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(clean); ip != nil {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("blocked private IP: %s", ip)
		}
		return ip.String(), nil
	}
	addrs, err := net.LookupHost(clean)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && !isPrivateIP(ip) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no safe IP resolved for %s", clean)
}

func grabBanner(host string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " ")
	if len(banner) > 120 {
		banner = banner[:120] + "..."
	}
	return banner
}

func (s *APIServer) handlePortScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		Host        string `json:"host"`
		Ports       []int  `json:"ports,omitempty"`
		TopPorts    bool   `json:"top_ports"`
		Concurrency int    `json:"concurrency"`
		TimeoutMs   int    `json:"timeout_ms"`
		GrabBanner  bool   `json:"grab_banner"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Host == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_HOST", "Missing Host", "host is required", "", nil)
		return
	}
	if !isSafeTarget("http://" + req.Host) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", "Private/loopback hosts are not permitted", "Use a public host", nil)
		return
	}
	dialHost, err := firstSafeResolvedIP(req.Host)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", err.Error(), "Use a public host", nil)
		return
	}
	if req.Concurrency <= 0 || req.Concurrency > 500 {
		req.Concurrency = 200
	}
	if req.TimeoutMs <= 0 || req.TimeoutMs > 5000 {
		req.TimeoutMs = 800
	}

	ports := req.Ports
	if len(ports) == 0 {
		for p := range commonPortServices {
			ports = append(ports, p)
		}
		// Add extra common web ports
		extras := []int{8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8090, 8181,
			8888, 9001, 9002, 9003, 9080, 9081, 4000, 4001, 3000, 3001, 5000, 5001}
		ports = append(ports, extras...)
		sort.Ints(ports)
	}
	if len(ports) > 10000 {
		writeProblem(w, r, http.StatusBadRequest, "ERR_TOO_MANY_PORTS", "Too Many Ports", "Maximum 10000 ports per scan", "", nil)
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	sem := make(chan struct{}, req.Concurrency)
	var mu sync.Mutex
	var results []PortResult
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(dialHost, strconv.Itoa(p)), timeout)
			if err != nil {
				return
			}
			conn.Close()

			res := PortResult{
				Port:    p,
				State:   "open",
				Service: commonPortServices[p],
			}
			if req.GrabBanner {
				res.Banner = grabBanner(dialHost, p, timeout+200*time.Millisecond)
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":       req.Host,
		"scanned":    len(ports),
		"open_count": len(results),
		"scan_time":  fmt.Sprintf("%.2fs", float64(req.TimeoutMs)*float64(req.Concurrency)/1000.0/float64(len(ports)+1)),
		"open_ports": results,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// DNS ENUMERATION
// ═══════════════════════════════════════════════════════════════════════════════

type DNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

var subdomainWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "webdisk",
	"ns", "vpn", "m", "smtp2", "blog", "dev", "staging", "api", "admin", "cdn",
	"app", "portal", "remote", "beta", "test", "secure", "server", "web", "shop",
	"forum", "cloud", "static", "media", "img", "images", "assets", "auth",
	"login", "docs", "git", "gitlab", "github", "jenkins", "jira", "confluence",
	"grafana", "prometheus", "kibana", "elastic", "monitoring", "dashboard",
	"backup", "db", "database", "mysql", "postgres", "redis", "mongo", "cache",
	"queue", "worker", "jobs", "cron", "internal", "intranet", "office", "support",
	"help", "status", "ping", "health", "metrics", "logs", "trace", "analytics",
	"v1", "v2", "v3", "prod", "production", "preview", "sandbox", "demo",
}

func (s *APIServer) handleDNSEnum(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		Domain         string   `json:"domain"`
		SubdomainBrute bool     `json:"subdomain_brute"`
		Concurrency    int      `json:"concurrency"`
		WordList       []string `json:"wordlist,omitempty"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Domain == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_DOMAIN", "Missing Domain", "domain is required", "", nil)
		return
	}
	if !isSafeTarget("http://" + req.Domain) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", "Private/loopback domains are not permitted", "Use a public domain or lab resolver", nil)
		return
	}
	if req.Concurrency <= 0 || req.Concurrency > 100 {
		req.Concurrency = 50
	}

	wordlist := req.WordList
	if len(wordlist) > 10000 {
		writeProblem(w, r, http.StatusBadRequest, "ERR_WORDLIST_TOO_LARGE", "Wordlist Too Large", "Maximum 10000 entries per wordlist", "Reduce wordlist size", nil)
		return
	}

	var records []DNSRecord

	// A records
	if addrs, err := net.LookupHost(req.Domain); err == nil {
		for _, a := range addrs {
			t := "A"
			if strings.Contains(a, ":") {
				t = "AAAA"
			}
			records = append(records, DNSRecord{Type: t, Value: a})
		}
	}

	// MX records
	if mxs, err := net.LookupMX(req.Domain); err == nil {
		for _, mx := range mxs {
			records = append(records, DNSRecord{Type: "MX", Value: fmt.Sprintf("%d %s", mx.Pref, mx.Host)})
		}
	}

	// NS records
	if nss, err := net.LookupNS(req.Domain); err == nil {
		for _, ns := range nss {
			records = append(records, DNSRecord{Type: "NS", Value: ns.Host})
		}
	}

	// TXT records
	if txts, err := net.LookupTXT(req.Domain); err == nil {
		for _, txt := range txts {
			records = append(records, DNSRecord{Type: "TXT", Value: txt})
		}
	}

	// CNAME
	if cname, err := net.LookupCNAME(req.Domain); err == nil && cname != req.Domain+"." {
		records = append(records, DNSRecord{Type: "CNAME", Value: cname})
	}

	// Reverse PTR for first A record
	if addrs, err := net.LookupHost(req.Domain); err == nil && len(addrs) > 0 {
		if ptrs, err := net.LookupAddr(addrs[0]); err == nil {
			for _, ptr := range ptrs {
				records = append(records, DNSRecord{Type: "PTR", Value: ptr})
			}
		}
	}

	// Subdomain brute force
	var foundSubs []map[string]interface{}
	if req.SubdomainBrute {
		sem := make(chan struct{}, req.Concurrency)
		var mu sync.Mutex
		var wg sync.WaitGroup
		if len(wordlist) == 0 {
			wordlist = subdomainWordlist
		}
		for _, sub := range wordlist {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				fqdn := s + "." + req.Domain
				addrs, err := net.LookupHost(fqdn)
				if err == nil && len(addrs) > 0 {
					mu.Lock()
					foundSubs = append(foundSubs, map[string]interface{}{
						"subdomain": fqdn,
						"ips":       addrs,
					})
					mu.Unlock()
				}
			}(sub)
		}
		wg.Wait()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain":     req.Domain,
		"records":    records,
		"subdomains": foundSubs,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSL / TLS AUDIT
// ═══════════════════════════════════════════════════════════════════════════════

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3 (INSECURE)"
	case tls.VersionTLS10:
		return "TLS 1.0 (DEPRECATED)"
	case tls.VersionTLS11:
		return "TLS 1.1 (DEPRECATED)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", v)
	}
}

func cipherSuiteName(id uint16) string {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name + " (INSECURE)"
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

func (s *APIServer) handleSSLAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Host == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_HOST", "Missing Host", "host is required", "", nil)
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if !isSafeTarget("https://" + net.JoinHostPort(req.Host, strconv.Itoa(req.Port))) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", "Private/loopback hosts are not permitted", "Use a public host", nil)
		return
	}
	dialHost, err := firstSafeResolvedIP(req.Host)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", err.Error(), "Use a public host", nil)
		return
	}
	addr := net.JoinHostPort(dialHost, strconv.Itoa(req.Port))

	// Try multiple TLS versions and collect what the server accepts
	type tlsProbeResult struct {
		Version   string `json:"version"`
		Accepted  bool   `json:"accepted"`
		CipherID  uint16 `json:"-"`
		CipherStr string `json:"cipher,omitempty"`
	}

	versionsToTest := []struct {
		min, max uint16
		name     string
	}{
		{tls.VersionTLS13, tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, tls.VersionTLS11, "TLS 1.1 (deprecated)"},
		{tls.VersionTLS10, tls.VersionTLS10, "TLS 1.0 (deprecated)"},
	}

	var probeResults []tlsProbeResult
	var certInfo map[string]interface{}
	var issues []string

	for _, v := range versionsToTest {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.min,
			MaxVersion:         v.max,
			ServerName:         req.Host,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
		if err != nil {
			probeResults = append(probeResults, tlsProbeResult{Version: v.name, Accepted: false})
			continue
		}
		cs := conn.ConnectionState()
		pr := tlsProbeResult{
			Version:   v.name,
			Accepted:  true,
			CipherID:  cs.CipherSuite,
			CipherStr: cipherSuiteName(cs.CipherSuite),
		}
		probeResults = append(probeResults, pr)

		if v.name == "TLS 1.1 (deprecated)" || v.name == "TLS 1.0 (deprecated)" {
			issues = append(issues, fmt.Sprintf("Server accepts %s — upgrade to TLS 1.2+ minimum", v.name))
		}

		// Extract cert info on first successful connection
		if certInfo == nil && len(cs.PeerCertificates) > 0 {
			cert := cs.PeerCertificates[0]
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			sans := cert.DNSNames
			sans = append(sans, cert.EmailAddresses...)

			certInfo = map[string]interface{}{
				"subject":              cert.Subject.CommonName,
				"issuer":               cert.Issuer.CommonName,
				"not_before":           cert.NotBefore.UTC().Format(time.RFC3339),
				"not_after":            cert.NotAfter.UTC().Format(time.RFC3339),
				"days_until_expiry":    daysLeft,
				"expired":              time.Now().After(cert.NotAfter),
				"self_signed":          cert.Issuer.CommonName == cert.Subject.CommonName,
				"wildcard":             strings.HasPrefix(cert.Subject.CommonName, "*."),
				"san":                  sans,
				"signature_algorithm":  cert.SignatureAlgorithm.String(),
				"serial":               cert.SerialNumber.String(),
				"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
			}

			if daysLeft < 14 {
				issues = append(issues, fmt.Sprintf("Certificate expires in %d days — renew immediately", daysLeft))
			} else if daysLeft < 30 {
				issues = append(issues, fmt.Sprintf("Certificate expires in %d days", daysLeft))
			}
			if cert.Issuer.CommonName == cert.Subject.CommonName {
				issues = append(issues, "Self-signed certificate — browsers will show a security warning")
			}
			if time.Now().After(cert.NotAfter) {
				issues = append(issues, "Certificate has EXPIRED — connections will be rejected by clients")
			}
		}
		conn.Close()
	}

	// Check for weak ciphers specifically
	weakCiphers := []string{}
	for _, r := range probeResults {
		if r.Accepted && (strings.Contains(r.CipherStr, "RC4") || strings.Contains(r.CipherStr, "3DES") ||
			strings.Contains(r.CipherStr, "NULL") || strings.Contains(r.CipherStr, "EXPORT") ||
			strings.Contains(r.CipherStr, "INSECURE")) {
			weakCiphers = append(weakCiphers, r.CipherStr)
			issues = append(issues, "Weak cipher suite negotiated: "+r.CipherStr)
		}
	}

	grade := "A"
	if len(issues) == 0 {
		grade = "A+"
	} else if len(issues) == 1 {
		grade = "A"
	} else if len(issues) <= 3 {
		grade = "B"
	} else if len(issues) <= 5 {
		grade = "C"
	} else {
		grade = "F"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":         req.Host,
		"port":         req.Port,
		"grade":        grade,
		"tls_probes":   probeResults,
		"certificate":  certInfo,
		"issues":       issues,
		"weak_ciphers": weakCiphers,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOST FINGERPRINT / OSINT
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleHostInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Target == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_TARGET", "Missing Target", "target is required", "", nil)
		return
	}
	if !isSafeTarget("http://" + req.Target) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", "Private/loopback hosts are not permitted", "", nil)
		return
	}
	dialHost, err := firstSafeResolvedIP(req.Target)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", err.Error(), "", nil)
		return
	}

	result := map[string]interface{}{}

	// Resolve IPs
	addrs, err := net.LookupHost(req.Target)
	if err == nil {
		result["ip_addresses"] = addrs
		// Reverse DNS
		var rdns []string
		for _, ip := range addrs {
			if ptrs, err := net.LookupAddr(ip); err == nil {
				rdns = append(rdns, ptrs...)
			}
		}
		result["reverse_dns"] = rdns
	}

	// HTTP probe on port 80
	httpInfo := map[string]interface{}{"available": false}
	client, _ := safeHTTPClient(6*time.Second, "http://"+req.Target)
	if client != nil {
		if resp, err := client.Get("http://" + req.Target); err == nil {
			defer resp.Body.Close()
			hdrs := map[string]string{}
			for k, v := range resp.Header {
				hdrs[k] = strings.Join(v, "; ")
			}
			httpInfo = map[string]interface{}{
				"available":    true,
				"status_code":  resp.StatusCode,
				"server":       resp.Header.Get("Server"),
				"powered_by":   resp.Header.Get("X-Powered-By"),
				"headers":      hdrs,
				"redirects_to": resp.Header.Get("Location"),
			}
		}
	}
	result["http"] = httpInfo

	// HTTPS probe
	httpsInfo := map[string]interface{}{"available": false}
	tlsClient, _ := safeHTTPClient(6*time.Second, "https://"+req.Target)
	if tlsClient != nil {
		if resp, err := tlsClient.Get("https://" + req.Target); err == nil {
			defer resp.Body.Close()
			hdrs := map[string]string{}
			for k, v := range resp.Header {
				hdrs[k] = strings.Join(v, "; ")
			}
			httpsInfo = map[string]interface{}{
				"available":   true,
				"status_code": resp.StatusCode,
				"server":      resp.Header.Get("Server"),
				"powered_by":  resp.Header.Get("X-Powered-By"),
				"headers":     hdrs,
			}
		}
	}
	result["https"] = httpsInfo

	// Port knock: common ports
	openPorts := []int{}
	quickPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range quickPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(dialHost, strconv.Itoa(port)), 800*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(openPorts)
	result["quick_open_ports"] = openPorts

	result["target"] = req.Target
	result["scanned_at"] = time.Now().UTC().Format(time.RFC3339)

	writeJSON(w, http.StatusOK, result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// WAYBACK MACHINE / INTERNET ARCHIVE
// ═══════════════════════════════════════════════════════════════════════════════

// WaybackSnapshot is one CDX record from the Wayback Machine.
type WaybackSnapshot struct {
	Timestamp  string `json:"timestamp"`
	DateTime   string `json:"datetime"`
	URL        string `json:"url,omitempty"`
	StatusCode string `json:"status_code,omitempty"`
}

// parseCDXTimestamp converts "20010117120000" → "2001-01-17 12:00:00 UTC".
func parseCDXTimestamp(ts string) string {
	if len(ts) < 14 {
		return ts
	}
	return fmt.Sprintf("%s-%s-%s %s:%s:%s UTC",
		ts[0:4], ts[4:6], ts[6:8], ts[8:10], ts[10:12], ts[12:14])
}

func cdxFetchSnapshot(targetURL string, latest bool, timeout time.Duration) *WaybackSnapshot {
	params := url.Values{}
	params.Set("url", targetURL)
	params.Set("output", "json")
	params.Set("limit", "1")
	params.Set("fl", "timestamp,original,statuscode")
	if latest {
		params.Set("fastLatest", "true")
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet,
		"https://web.archive.org/cdx/search/cdx?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "mega-analyzer/security-research")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	var rows [][]string
	if json.Unmarshal(body, &rows) != nil || len(rows) < 2 {
		return nil
	}
	data := rows[1]
	snap := &WaybackSnapshot{}
	if len(data) > 0 {
		snap.Timestamp = data[0]
		snap.DateTime = parseCDXTimestamp(data[0])
	}
	if len(data) > 1 {
		snap.URL = data[1]
	}
	if len(data) > 2 {
		snap.StatusCode = data[2]
	}
	return snap
}

func cdxFetchPageCount(targetURL string, timeout time.Duration) int {
	params := url.Values{}
	params.Set("url", targetURL)
	params.Set("output", "json")
	params.Set("showNumPages", "true")
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet,
		"https://web.archive.org/cdx/search/cdx?"+params.Encode(), nil)
	if err != nil {
		return -1
	}
	req.Header.Set("User-Agent", "mega-analyzer/security-research")
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	var n int
	if json.Unmarshal([]byte(strings.TrimSpace(string(body))), &n) == nil {
		return n
	}
	return -1
}

func (s *APIServer) handleWaybackInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.URL == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_URL", "Missing URL", "url is required", "", nil)
		return
	}

	target := req.URL
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	var (
		first, last *WaybackSnapshot
		pages       int
		wg          sync.WaitGroup
		mu          sync.Mutex
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		snap := cdxFetchSnapshot(target, false, 10*time.Second)
		mu.Lock()
		first = snap
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		snap := cdxFetchSnapshot(target, true, 10*time.Second)
		mu.Lock()
		last = snap
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		n := cdxFetchPageCount(target, 10*time.Second)
		mu.Lock()
		pages = n
		mu.Unlock()
	}()
	wg.Wait()

	approxTotal := -1
	if pages > 0 {
		approxTotal = pages * 100000
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":                    req.URL,
		"first_snapshot":         first,
		"last_snapshot":          last,
		"approx_total_snapshots": approxTotal,
		"wayback_url":            "https://web.archive.org/web/*/" + req.URL,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// SITE PROFILE (security headers, tech detection, robots.txt, well-known)
// Tech fingerprinting lives in tech_fingerprint.go.
// ═══════════════════════════════════════════════════════════════════════════════

type secHeaderResult struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Note    string `json:"note"`
}

var secHeaderDefs = []struct{ header, note string }{
	{"Strict-Transport-Security", "HSTS – enforces HTTPS and prevents SSL-stripping"},
	{"Content-Security-Policy", "CSP – restricts resource origins, prevents XSS"},
	{"X-Frame-Options", "Prevents clickjacking via iframe embedding"},
	{"X-Content-Type-Options", "Stops MIME-type sniffing attacks"},
	{"Referrer-Policy", "Controls referrer leakage to third parties"},
	{"Permissions-Policy", "Restricts browser feature access (camera, mic…)"},
	{"Cross-Origin-Resource-Policy", "CORP – limits cross-origin resource reads"},
	{"Cross-Origin-Opener-Policy", "COOP – isolates browsing context from opener"},
}

func auditSecHeaders(headers http.Header) ([]secHeaderResult, int) {
	results := make([]secHeaderResult, 0, len(secHeaderDefs))
	present := 0
	for _, def := range secHeaderDefs {
		val := headers.Get(def.header)
		ok := val != ""
		if ok {
			present++
		}
		results = append(results, secHeaderResult{
			Header:  def.header,
			Present: ok,
			Value:   val,
			Note:    def.note,
		})
	}
	return results, present
}

func fetchSmallText(baseURL, path string, client *http.Client) string {
	resp, err := client.Get(baseURL + path)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return strings.TrimSpace(string(body))
}

func parseRobots(content string) (disallowPaths, sitemaps []string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"):
			p := strings.TrimSpace(line[9:])
			if p != "" && p != "/" {
				disallowPaths = append(disallowPaths, p)
			}
		case strings.HasPrefix(lower, "sitemap:"):
			s := strings.TrimSpace(line[8:])
			if s != "" {
				sitemaps = append(sitemaps, s)
			}
		}
	}
	return
}

func (s *APIServer) handleSiteProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.URL == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_URL", "Missing URL", "url is required", "", nil)
		return
	}

	baseURL := req.URL
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	parsedURL, err := url.Parse(baseURL)
	if err != nil || !isSafeTarget(baseURL) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_URL", "Invalid URL", "must be a safe public URL", "", nil)
		return
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	result := map[string]interface{}{
		"url":        req.URL,
		"host":       parsedURL.Host,
		"scanned_at": time.Now().UTC().Format(time.RFC3339),
	}

	// Probe main page
	if resp, err := client.Get(baseURL); err == nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		body := string(bodyBytes)

		detections := fingerprintSite(resp.Header, resp.Cookies(), body)
		techs := make([]string, 0, len(detections))
		for _, d := range detections {
			label := d.Name
			if d.Version != "" {
				label += " " + d.Version
			}
			techs = append(techs, label)
		}
		result["technologies"] = techs
		result["tech_stack"] = detections
		if summary := techSummary(detections); summary != "" {
			result["stack_summary"] = summary
		}
		if title := extractPageTitle(body); title != "" {
			result["title"] = title
		}

		secChecks, presentCount := auditSecHeaders(resp.Header)
		result["security_headers"] = map[string]interface{}{
			"score":  fmt.Sprintf("%d/%d", presentCount, len(secHeaderDefs)),
			"checks": secChecks,
		}

		result["status_code"] = resp.StatusCode
		result["final_url"] = resp.Request.URL.String()
		result["server"] = resp.Header.Get("Server")
		result["powered_by"] = resp.Header.Get("X-Powered-By")
	}

	// robots.txt
	robots := fetchSmallText(baseURL, "/robots.txt", client)
	if robots != "" {
		disallows, sitemaps := parseRobots(robots)
		result["robots_txt"] = map[string]interface{}{
			"found":          true,
			"disallow_paths": disallows,
			"sitemaps":       sitemaps,
		}
	} else {
		result["robots_txt"] = map[string]interface{}{"found": false}
	}

	// security.txt (RFC 9116)
	secTxt := fetchSmallText(baseURL, "/.well-known/security.txt", client)
	if secTxt == "" {
		secTxt = fetchSmallText(baseURL, "/security.txt", client)
	}
	truncated := secTxt
	if len(truncated) > 500 {
		truncated = truncated[:500] + "…"
	}
	result["security_txt"] = map[string]interface{}{
		"found":   secTxt != "",
		"content": truncated,
	}

	// ads.txt and sitemap.xml presence
	result["ads_txt"] = map[string]interface{}{
		"found": fetchSmallText(baseURL, "/ads.txt", client) != "",
	}
	result["sitemap_xml"] = map[string]interface{}{
		"found": fetchSmallText(baseURL, "/sitemap.xml", client) != "",
	}

	writeJSON(w, http.StatusOK, result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// RDAP – DOMAIN REGISTRATION INFO
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleRDAPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Domain == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_DOMAIN", "Missing Domain", "domain is required", "", nil)
		return
	}
	// Strip scheme and path, keep just the registrable domain
	domain := strings.ToLower(req.Domain)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	if i := strings.IndexByte(domain, '/'); i >= 0 {
		domain = domain[:i]
	}

	client := &http.Client{Timeout: 10 * time.Second}
	rdapReq, _ := http.NewRequest(http.MethodGet, "https://rdap.org/domain/"+url.PathEscape(domain), nil)
	rdapReq.Header.Set("Accept", "application/json")
	rdapReq.Header.Set("User-Agent", "mega-analyzer/security-research")

	resp, err := client.Do(rdapReq)
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "ERR_RDAP_UNAVAILABLE", "RDAP Unreachable", err.Error(), "Check network connectivity", nil)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	var rdap map[string]interface{}
	if json.Unmarshal(body, &rdap) != nil || resp.StatusCode != http.StatusOK {
		writeProblem(w, r, http.StatusNotFound, "ERR_RDAP_NOT_FOUND", "Domain Not Found", "RDAP returned no data for "+domain, "", nil)
		return
	}

	result := map[string]interface{}{"domain": domain}

	// Extract events (registration, expiry, last changed)
	if events, ok := rdap["events"].([]interface{}); ok {
		dates := map[string]string{}
		for _, ev := range events {
			e, _ := ev.(map[string]interface{})
			action, _ := e["eventAction"].(string)
			date, _ := e["eventDate"].(string)
			switch action {
			case "registration":
				dates["registered"] = date
			case "expiration":
				dates["expires"] = date
			case "last changed":
				dates["last_updated"] = date
			}
		}
		result["dates"] = dates
	}

	// Registrar
	if entities, ok := rdap["entities"].([]interface{}); ok {
		for _, ent := range entities {
			e, _ := ent.(map[string]interface{})
			roles, _ := e["roles"].([]interface{})
			for _, role := range roles {
				if role == "registrar" {
					if fn, ok := e["fn"].(string); ok {
						result["registrar"] = fn
					}
				}
			}
		}
	}

	// Status flags
	if statuses, ok := rdap["status"].([]interface{}); ok {
		ss := make([]string, 0, len(statuses))
		for _, s := range statuses {
			if sv, ok := s.(string); ok {
				ss = append(ss, sv)
			}
		}
		result["status"] = ss
	}

	// Name servers
	if ns, ok := rdap["nameservers"].([]interface{}); ok {
		names := []string{}
		for _, n := range ns {
			nm, _ := n.(map[string]interface{})
			if ldhName, ok := nm["ldhName"].(string); ok {
				names = append(names, strings.ToLower(ldhName))
			}
		}
		result["nameservers"] = names
	}

	writeJSON(w, http.StatusOK, result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HTML AUDIT – secrets, trackers, endpoints, reCAPTCHA, Cloudflare
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// JS DEOBFUSCATION — static, no code execution
// ═══════════════════════════════════════════════════════════════════════════════

// Safety limits — prevent a crafted site from OOMing the analyzer.
const (
	maxDeobfInputBytes  = 3 * 1024 * 1024 // skip deobf if file > 3 MB
	maxDeobfOutputBytes = 6 * 1024 * 1024 // abandon if result grows beyond 6 MB
	maxStrArraySubs     = 5_000           // cap string-array substitutions
	maxJSBundleBytes    = 2 * 1024 * 1024 // max download size per JS bundle
	maxJSBundles        = 12              // max JS bundles to fetch
	maxSourceMapBytes   = 5 * 1024 * 1024 // max source-map file download
	maxSourceFiles      = 5               // max sourcesContent entries to scan
	maxSourceFileBytes  = 512 * 1024      // max bytes per individual source file
)

var (
	deobfHexRe     = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	deobfUnicodeRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	deobfAtobRe    = regexp.MustCompile(`atob\(["']([A-Za-z0-9+/=]{4,})["']\)`)
	deobfConcatRe  = regexp.MustCompile(`"([^"\\]{0,300})"\s*\+\s*"([^"\\]{0,300})"`)
	deobfArrayRe   = regexp.MustCompile(`(?:var\s+)?(\w+)\s*=\s*"([^"]{20,})"\s*\.split\s*\(\s*["']([^"']{1,3})["']\s*\)`)
	// String.fromCharCode(115,107,45,...) → decode char codes
	deobfFromCharRe = regexp.MustCompile(`String\.fromCharCode\(([\d\s,]{2,200})\)`)
	// Template literals without ${} interpolation: `literal text` → "literal text"
	deobfTplLitRe = regexp.MustCompile("`" + `([^` + "`" + `$\\]{4,})` + "`")
	// URL percent-encoding: at least 3 consecutive %XX tokens
	deobfPctEncRe = regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)
	// //# sourceMappingURL= reference inside JS
	sourceMappingURLRe = regexp.MustCompile(`//# sourceMappingURL=([^\s"'<>]{4,})`)
)

// DeobfResult holds the transformed source and a list of applied passes.
type DeobfResult struct {
	Source string   `json:"source"`
	Passes []string `json:"passes_applied"`
}

// deobfuscateJS applies lightweight static deobfuscation passes.
// No code is executed — all transformations are purely textual/regex-based.
//
//	Pass 1  \xNN hex escape literals           →  printable character
//	Pass 2  \uNNNN unicode escapes             →  UTF-8 character
//	Pass 3  String.fromCharCode(115,107,…)     →  "sk…"
//	Pass 4  atob("b64")                        →  decoded string literal
//	Pass 5  %hex URL percent-encoding (3+ seq) →  decoded text
//	Pass 6  `template literal` (no ${})        →  "template literal"
//	Pass 7  string-array substitution          →  c[42] → "actualValue"
//	Pass 8  string concatenation folding       →  "a"+"b" → "ab"
func deobfuscateJS(src string) DeobfResult {
	if len(src) > maxDeobfInputBytes {
		return DeobfResult{Source: src, Passes: []string{"skipped:too_large"}}
	}
	var passes []string
	orig := src

	apply := func(label, next string) {
		if next != src && len(next) <= maxDeobfOutputBytes {
			passes = append(passes, label)
			src = next
		}
	}

	// Pass 1: \xNN hex escapes
	apply("hex_escapes", deobfHexRe.ReplaceAllStringFunc(src, func(m string) string {
		val, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return m
		}
		r := rune(val)
		if r >= 0x20 && r != 0x22 && r != 0x5c && r != '<' && r != '>' {
			return string(r)
		}
		return m
	}))

	// Pass 2: \uNNNN unicode escapes
	apply("unicode_escapes", deobfUnicodeRe.ReplaceAllStringFunc(src, func(m string) string {
		val, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil {
			return m
		}
		r := rune(val)
		if r >= 0x20 && r != 0x22 && r != 0x5c {
			return string(r)
		}
		return m
	}))

	// Pass 3: String.fromCharCode(115, 107, 45, ...)
	apply("fromCharCode", deobfFromCharRe.ReplaceAllStringFunc(src, func(m string) string {
		sub := deobfFromCharRe.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		var buf []byte
		for _, part := range strings.Split(sub[1], ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 0x20 || n > 0x7e {
				return m // bail on non-printable — keep original
			}
			buf = append(buf, byte(n))
		}
		if len(buf) == 0 {
			return m
		}
		return `"` + strings.ReplaceAll(string(buf), `"`, `\"`) + `"`
	}))

	// Pass 4: atob("base64literal")
	apply("atob_literals", deobfAtobRe.ReplaceAllStringFunc(src, func(m string) string {
		sub := deobfAtobRe.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		decoded, err := base64.StdEncoding.DecodeString(sub[1])
		if err != nil {
			return m
		}
		for _, b := range decoded {
			if b < 0x20 || b > 0x7e {
				return m
			}
		}
		return `"` + strings.ReplaceAll(string(decoded), `"`, `\"`) + `"`
	}))

	// Pass 5: URL percent-encoding (at least 3 consecutive %XX → printable text)
	apply("pct_encoding", deobfPctEncRe.ReplaceAllStringFunc(src, func(m string) string {
		decoded, err := url.QueryUnescape(m)
		if err != nil {
			return m
		}
		for _, b := range []byte(decoded) {
			if b < 0x20 || b > 0x7e {
				return m
			}
		}
		return decoded
	}))

	// Pass 6: simple template literals without ${ interpolation
	// `raw text` → "raw text"
	apply("template_literals", deobfTplLitRe.ReplaceAllStringFunc(src, func(m string) string {
		inner := m[1 : len(m)-1] // strip backticks
		inner = strings.ReplaceAll(inner, `"`, `\"`)
		return `"` + inner + `"`
	}))

	// Pass 7: string-array substitution
	// var c = "a;b;c".split(";")  →  c[0]→"a", c[1]→"b" ...
	if m := deobfArrayRe.FindStringSubmatch(src); m != nil {
		varName, content, sep := m[1], m[2], m[3]
		parts := strings.Split(content, sep)
		if len(parts) > 2 {
			idxRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\[(\d+)\]`)
			count := 0
			next := idxRe.ReplaceAllStringFunc(src, func(access string) string {
				if count >= maxStrArraySubs {
					return access
				}
				sub := idxRe.FindStringSubmatch(access)
				if len(sub) < 2 {
					return access
				}
				idx, err := strconv.Atoi(sub[1])
				if err != nil || idx < 0 || idx >= len(parts) {
					return access
				}
				count++
				return `"` + parts[idx] + `"`
			})
			if count > 0 && len(next) <= maxDeobfOutputBytes {
				passes = append(passes, fmt.Sprintf("string_array(%d/%d subs, var=%s)", count, len(parts), varName))
				src = next
			}
		}
	}

	// Pass 8: fold adjacent string literals "a" + "b" → "ab" (up to 12 rounds)
	prev := src
	for i := 0; i < 12; i++ {
		next := deobfConcatRe.ReplaceAllString(src, `"$1$2"`)
		if next == src || len(next) > maxDeobfOutputBytes {
			break
		}
		src = next
	}
	if src != prev {
		passes = append(passes, "concat_folding")
	}

	if src == orig {
		passes = []string{"none"}
	}
	return DeobfResult{Source: src, Passes: passes}
}

// resolveURL resolves ref (possibly relative) against the base URL.
func resolveURL(base, ref string) string {
	baseU, err := url.Parse(base)
	if err != nil {
		return ""
	}
	refU, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return baseU.ResolveReference(refU).String()
}

// fetchAndScanSourceMap downloads a .map file and scans sourcesContent for secrets.
// Source maps often contain the original pre-minification source code.
func fetchAndScanSourceMap(mapURL string, client *http.Client) (findings []htmlFinding, srcNames []string) {
	if !isSafeTarget(mapURL) {
		return
	}
	req, err := http.NewRequest(http.MethodGet, mapURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; mega-analyzer/1.0; +security-research)")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxSourceMapBytes))

	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if json.Unmarshal(body, &sm) != nil {
		return
	}
	srcNames = sm.Sources

	for i, content := range sm.SourcesContent {
		if i >= maxSourceFiles {
			break
		}
		if content == "" {
			continue
		}
		if len(content) > maxSourceFileBytes {
			content = content[:maxSourceFileBytes]
		}
		label := mapURL
		if i < len(sm.Sources) {
			label = "sourcemap://" + sm.Sources[i]
		}
		// Also deobfuscate individual source files before scanning
		deobf := deobfuscateJS(content)
		findings = append(findings, scanContent(deobf.Source, label)...)
	}
	return
}

// htmlSecretRe holds compiled patterns for secrets in HTML/JS source.
var htmlSecretRe = []*secretPattern{
	{Name: "AWS Access Key", Severity: "CRITICAL", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "Google API Key", Severity: "HIGH", re: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{Name: "GitHub Token", Severity: "CRITICAL", re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`)},
	{Name: "Stripe Secret Key", Severity: "CRITICAL", re: regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24,99}`)},
	{Name: "Slack Token", Severity: "HIGH", re: regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9A-Za-z\-]{24,}`)},
	{Name: "JWT Token", Severity: "MEDIUM", re: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{Name: "Private Key Block", Severity: "CRITICAL", re: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{Name: "SendGrid API Key", Severity: "HIGH", re: regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`)},
	{Name: "HuggingFace Token", Severity: "HIGH", re: regexp.MustCompile(`hf_[A-Za-z0-9]{37,}`)},
	{Name: "Anthropic API Key", Severity: "CRITICAL", re: regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{20,}`)},
	{Name: "OpenAI API Key", Severity: "CRITICAL", re: regexp.MustCompile(`sk-proj-[A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9]{48}`)},
	{Name: "Source Map Reference", Severity: "LOW", re: regexp.MustCompile(`//# sourceMappingURL=([^\s"']+\.map)`)},
	{Name: "Internal IP Address", Severity: "MEDIUM", re: regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)},
	{Name: "GraphQL Endpoint", Severity: "INFO", re: regexp.MustCompile(`(?i)["'` + "`" + `](/[a-zA-Z0-9_\-/]*graphql[a-zA-Z0-9_\-/]*)["'` + "`" + `]`)},
	{Name: "API Endpoint", Severity: "INFO", re: regexp.MustCompile(`(?i)["'` + "`" + `](/api/v?\d?[a-zA-Z0-9/_\-]{3,60})["'` + "`" + `]`)},
	{Name: "HTML Comment Leak", Severity: "LOW", re: regexp.MustCompile(`<!--[^>]{3,200}(?i)(?:password|passwd|secret|token|key|admin|todo|fixme|hack)[^>]{0,200}-->`)},
}

type secretPattern struct {
	Name     string
	Severity string
	re       *regexp.Regexp
}

type htmlFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
	Source   string `json:"source,omitempty"` // "html" or the JS URL
	Offset   int    `json:"offset,omitempty"`
}

// scriptSrcRe finds <script src="..."> URLs including JS modules.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)["']`)

// knownCDNs are well-known third-party CDN domains — we skip their scripts
// since library code (jQuery, React, Bootstrap) won't contain app secrets.
var knownCDNs = []string{
	"cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
	"ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
	"maxcdn.bootstrapcdn.com", "use.fontawesome.com", "fonts.googleapis.com",
	"connect.facebook.net", "platform.twitter.com", "googletagmanager.com",
	"google-analytics.com", "static.hotjar.com", "browser.sentry-cdn.com",
	"js.stripe.com", "cdn.amplitude.com", "cdn.segment.com",
}

func isKnownCDN(u string) bool {
	lu := strings.ToLower(u)
	for _, cdn := range knownCDNs {
		if strings.Contains(lu, cdn) {
			return true
		}
	}
	return false
}

// extractScriptURLs extracts all non-CDN <script src> URLs from HTML and
// resolves relative URLs against pageURL. Returns at most maxScripts URLs.
func extractScriptURLs(htmlBody, pageURL string, maxScripts int) []string {
	pageU, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	matches := scriptSrcRe.FindAllStringSubmatch(htmlBody, -1)
	seen := map[string]bool{}
	var urls []string
	for _, m := range matches {
		src := strings.TrimSpace(m[1])
		if src == "" || strings.HasPrefix(src, "data:") {
			continue
		}
		if !strings.HasPrefix(src, "http") {
			refU, err := url.Parse(src)
			if err != nil {
				continue
			}
			src = pageU.ResolveReference(refU).String()
		}
		if isKnownCDN(src) || !isSafeTarget(src) || seen[src] {
			continue
		}
		seen[src] = true
		urls = append(urls, src)
		if len(urls) >= maxScripts {
			break
		}
	}
	return urls
}

func scanContent(content, source string) []htmlFinding {
	var findings []htmlFinding
	for _, sp := range htmlSecretRe {
		locs := sp.re.FindAllStringIndex(content, 10)
		for _, loc := range locs {
			match := content[loc[0]:loc[1]]
			if len(match) > 120 {
				match = match[:120] + "…"
			}
			findings = append(findings, htmlFinding{
				Type:     sp.Name,
				Severity: sp.Severity,
				Match:    match,
				Source:   source,
				Offset:   loc[0],
			})
		}
	}
	return findings
}

// trackerDefs maps tracker name → patterns that appear in HTML/JS.
var trackerDefs = []struct {
	Name     string
	Category string
	Patterns []string
}{
	{"Google Analytics (GA4)", "Analytics", []string{"gtag/js", "google-analytics.com/g/", "gtag("}},
	{"Google Analytics (UA)", "Analytics", []string{"google-analytics.com/analytics.js", "ga.js", "_gaq.push"}},
	{"Facebook Pixel", "Advertising", []string{"connect.facebook.net", "fbq(", "facebook.com/tr"}},
	{"Hotjar", "Session Recording", []string{"hotjar.com", "hj(", "_hjSettings"}},
	{"Microsoft Clarity", "Session Recording", []string{"clarity.ms", "clarity(", "clarity.js"}},
	{"Mixpanel", "Analytics", []string{"mixpanel.init", "cdn.mxpnl.com", "api.mixpanel.com"}},
	{"Amplitude", "Analytics", []string{"amplitude.com/libs", "amplitude.init", "cdn.amplitude.com"}},
	{"Segment", "Data Platform", []string{"segment.com/analytics.js", "analytics.identify("}},
	{"TikTok Pixel", "Advertising", []string{"tiktok.com/i/", "ttq.load", "analytics.tiktok.com"}},
	{"Twitter/X Pixel", "Advertising", []string{"analytics.twitter.com", "twq("}},
	{"LinkedIn Insight", "Advertising", []string{"snap.licdn.com", "_linkedin_partner_id"}},
	{"Criteo", "Advertising", []string{"static.criteo.net", "criteo.com"}},
	{"DoubleClick/DV360", "Advertising", []string{"doubleclick.net", "googleads.g.doubleclick"}},
	{"Yandex Metrica", "Analytics", []string{"mc.yandex.ru", "ym("}},
	{"Intercom", "Support Chat", []string{"widget.intercom.io", "Intercom("}},
	{"Zendesk", "Support Chat", []string{"static.zdassets.com", "zopim.com"}},
	{"Stripe", "Payment", []string{"js.stripe.com"}},
	{"PayPal", "Payment", []string{"paypalobjects.com", "paypal.com/sdk"}},
	{"Sentry", "Error Tracking", []string{"browser.sentry-cdn.com", "Sentry.init"}},
	{"Datadog RUM", "Monitoring", []string{"datadoghq-browser-agent.com", "DD_RUM.init"}},
}

type trackerFound struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

func detectTrackers(body string) []trackerFound {
	var found []trackerFound
	lower := strings.ToLower(body)
	for _, td := range trackerDefs {
		for _, pat := range td.Patterns {
			if strings.Contains(lower, strings.ToLower(pat)) {
				found = append(found, trackerFound{Name: td.Name, Category: td.Category})
				break
			}
		}
	}
	return found
}

// detectCaptcha checks for reCAPTCHA and hCaptcha in HTML.
func detectCaptcha(body, lowerBody string) map[string]interface{} {
	result := map[string]interface{}{
		"recaptcha": false,
		"hcaptcha":  false,
		"turnstile": false,
		"other":     []string{},
	}
	if strings.Contains(lowerBody, "recaptcha/api.js") || strings.Contains(lowerBody, "g-recaptcha") ||
		strings.Contains(lowerBody, "grecaptcha.") || strings.Contains(lowerBody, "data-sitekey") {
		result["recaptcha"] = true
	}
	if strings.Contains(lowerBody, "hcaptcha.com") || strings.Contains(lowerBody, "h-captcha") {
		result["hcaptcha"] = true
	}
	if strings.Contains(lowerBody, "challenges.cloudflare.com/turnstile") || strings.Contains(lowerBody, "cf-turnstile") {
		result["turnstile"] = true
	}
	return result
}

// detectCloudflare checks for Cloudflare protection signals in HTML + headers.
func detectCloudflare(body, lowerBody string, headers http.Header) map[string]interface{} {
	result := map[string]interface{}{"detected": false, "signals": []string{}}
	var signals []string

	if headers.Get("CF-Ray") != "" {
		signals = append(signals, "CF-Ray header present")
	}
	if strings.Contains(headers.Get("Server"), "cloudflare") {
		signals = append(signals, "Server: cloudflare")
	}
	if strings.Contains(lowerBody, "__cf_bm") || strings.Contains(lowerBody, "__cfduid") {
		signals = append(signals, "Cloudflare cookie found in HTML")
	}
	if strings.Contains(lowerBody, "challenges.cloudflare.com") {
		signals = append(signals, "Cloudflare challenge page (bot protection active)")
	}
	if strings.Contains(lowerBody, "cdn-cgi/") {
		signals = append(signals, "Cloudflare CDN-CGI path found")
	}
	if len(signals) > 0 {
		result["detected"] = true
		result["signals"] = signals
	}
	return result
}

var formRe = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)
var formPostMethodRe = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']?post["']?`)
var csrfInputRe = regexp.MustCompile(`(?i)(?:csrf|_token|authenticity_token|nonce)`)

func findFormsWithoutCSRF(body string) int {
	forms := formRe.FindAllString(body, -1)
	missing := 0
	for _, form := range forms {
		if formPostMethodRe.MatchString(form) && !csrfInputRe.MatchString(form) {
			missing++
		}
	}
	return missing
}

func (s *APIServer) handleHTMLAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.URL == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_URL", "Missing URL", "url is required", "", nil)
		return
	}

	target := req.URL
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	if !isSafeTarget(target) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", "Private/loopback hosts not permitted", "", nil)
		return
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	httpReq, _ := http.NewRequest(http.MethodGet, target, nil)
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; mega-analyzer/1.0; +security-research)")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(httpReq)
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "ERR_FETCH_FAILED", "Fetch Failed", err.Error(), "Check the URL and try again", nil)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	rawHTML := string(body)
	finalURL := resp.Request.URL.String()

	// Deobfuscate the HTML body (catches \xNN and atob() in inline <script> blocks)
	htmlDeobf := deobfuscateJS(rawHTML)
	bodyStr := htmlDeobf.Source
	lowerBody := strings.ToLower(bodyStr)

	// Scan HTML (including inline scripts) for secrets
	findings := scanContent(bodyStr, "html")

	// Extract JS bundle URLs (skip known CDNs, max 12 files)
	jsURLs := extractScriptURLs(bodyStr, finalURL, 12)

	// Download, deobfuscate and scan JS bundles concurrently
	type sourceMapResult struct {
		URL      string        `json:"url"`
		Sources  []string      `json:"sources,omitempty"`
		Findings []htmlFinding `json:"findings"`
	}
	type jsBundleResult struct {
		URL         string           `json:"url"`
		SizeBytes   int              `json:"size_bytes"`
		DeobfPasses []string         `json:"deobf_passes"`
		SourceMap   *sourceMapResult `json:"source_map,omitempty"`
		Findings    []htmlFinding    `json:"findings"`
	}
	var jsBundles []jsBundleResult
	var jsMu sync.Mutex
	var jsWg sync.WaitGroup
	jsSem := make(chan struct{}, 5)

	for _, jsURL := range jsURLs {
		jsWg.Add(1)
		go func(u string) {
			defer jsWg.Done()
			jsSem <- struct{}{}
			defer func() { <-jsSem }()

			jsReq, _ := http.NewRequest(http.MethodGet, u, nil)
			jsReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; mega-analyzer/1.0; +security-research)")
			jsResp, err := client.Do(jsReq)
			if err != nil {
				return
			}
			defer jsResp.Body.Close()
			jsBody, _ := io.ReadAll(io.LimitReader(jsResp.Body, maxJSBundleBytes))
			jsRaw := string(jsBody)

			// Deobfuscate before scanning
			deobf := deobfuscateJS(jsRaw)
			jsFindings := scanContent(deobf.Source, u)

			bundle := jsBundleResult{
				URL:         u,
				SizeBytes:   len(jsBody),
				DeobfPasses: deobf.Passes,
				Findings:    jsFindings,
			}

			// Check for source map reference and scan it
			if sm := sourceMappingURLRe.FindStringSubmatch(jsRaw); sm != nil {
				mapURL := resolveURL(u, sm[1])
				if mapURL != "" {
					smFindings, smSources := fetchAndScanSourceMap(mapURL, client)
					bundle.SourceMap = &sourceMapResult{
						URL:      mapURL,
						Sources:  smSources,
						Findings: smFindings,
					}
					jsFindings = append(jsFindings, smFindings...)
				}
			}

			jsMu.Lock()
			jsBundles = append(jsBundles, bundle)
			findings = append(findings, jsFindings...)
			jsMu.Unlock()
		}(jsURL)
	}
	jsWg.Wait()

	// Sort all findings by severity
	severityOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.Slice(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	// Tracker detection (HTML + inline JS)
	trackers := detectTrackers(bodyStr)

	// CAPTCHA and Cloudflare detection
	captcha := detectCaptcha(bodyStr, lowerBody)
	cf := detectCloudflare(bodyStr, lowerBody, resp.Header)

	// CSRF check on forms
	formsWithoutCSRF := findFormsWithoutCSRF(bodyStr)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":                req.URL,
		"final_url":          finalURL,
		"status_code":        resp.StatusCode,
		"content_type":       resp.Header.Get("Content-Type"),
		"html_size_bytes":    len(body),
		"html_deobf_passes":  htmlDeobf.Passes,
		"js_bundles_scanned": jsBundles,
		"secrets_found":      findings,
		"trackers":           trackers,
		"captcha":            captcha,
		"cloudflare":         cf,
		"forms_missing_csrf": formsWithoutCSRF,
		"scanned_at":         time.Now().UTC().Format(time.RFC3339),
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE SCANNER – probe for exposed sensitive files
// ═══════════════════════════════════════════════════════════════════════════════

type exposedFile struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	SizeBytes  int    `json:"size_bytes,omitempty"`
	Severity   string `json:"severity"`
	Preview    string `json:"preview,omitempty"`
	Note       string `json:"note"`
}

var sensitivePaths = []struct {
	path, severity, note string
}{
	// Source control
	{"/.git/config", "CRITICAL", "Git config – may expose remote URL with credentials"},
	{"/.git/HEAD", "HIGH", "Git HEAD – confirms git repo is exposed"},
	{"/.git/COMMIT_EDITMSG", "MEDIUM", "Exposed git commit message"},
	{"/.svn/entries", "HIGH", "SVN metadata exposed"},
	{"/.hg/hgrc", "HIGH", "Mercurial config exposed"},

	// Environment & secrets
	{"/.env", "CRITICAL", "Environment file – often contains DB passwords, API keys"},
	{"/.env.local", "CRITICAL", "Local environment file"},
	{"/.env.production", "CRITICAL", "Production environment file"},
	{"/.env.backup", "CRITICAL", "Environment backup file"},
	{"/config.env", "CRITICAL", "Config environment file"},

	// Database
	{"/dump.sql", "CRITICAL", "SQL database dump"},
	{"/database.sql", "CRITICAL", "SQL database dump"},
	{"/backup.sql", "CRITICAL", "SQL backup"},
	{"/db.sql", "CRITICAL", "SQL database file"},

	// Backup archives
	{"/backup.zip", "CRITICAL", "Backup archive"},
	{"/backup.tar.gz", "CRITICAL", "Backup archive"},
	{"/www.zip", "HIGH", "Website backup archive"},
	{"/site.zip", "HIGH", "Website backup archive"},
	{"/htdocs.zip", "HIGH", "Website backup archive"},

	// Config files
	{"/wp-config.php", "CRITICAL", "WordPress config with DB credentials"},
	{"/wp-config.php.bak", "CRITICAL", "WordPress config backup"},
	{"/config.php", "HIGH", "PHP config file"},
	{"/configuration.php", "HIGH", "Joomla config"},
	{"/app/etc/local.xml", "HIGH", "Magento config"},
	{"/appsettings.json", "HIGH", "ASP.NET application settings"},
	{"/web.config", "MEDIUM", "IIS/ASP.NET config"},
	{"/application.yml", "HIGH", "Spring Boot config"},
	{"/application.properties", "HIGH", "Spring Boot properties"},

	// Auth files
	{"/.htpasswd", "CRITICAL", "HTTP Basic Auth credentials"},
	{"/.htaccess", "MEDIUM", "Apache access rules"},

	// Debug / info pages
	{"/phpinfo.php", "HIGH", "PHP info page – exposes server config"},
	{"/info.php", "HIGH", "PHP info page"},
	{"/php-info.php", "HIGH", "PHP info page"},
	{"/server-status", "MEDIUM", "Apache server status"},
	{"/server-info", "MEDIUM", "Apache server info"},

	// API documentation
	{"/swagger.json", "MEDIUM", "Swagger/OpenAPI spec – lists all endpoints"},
	{"/swagger.yaml", "MEDIUM", "Swagger/OpenAPI spec"},
	{"/openapi.json", "MEDIUM", "OpenAPI spec"},
	{"/api-docs", "MEDIUM", "API documentation"},
	{"/v1/swagger.json", "MEDIUM", "API v1 Swagger spec"},
	{"/api/swagger.json", "MEDIUM", "API Swagger spec"},
	{"/graphql", "INFO", "GraphQL endpoint (may allow introspection)"},

	// Misc sensitive
	{"/.DS_Store", "LOW", "macOS metadata – reveals directory structure"},
	{"/crossdomain.xml", "INFO", "Flash cross-domain policy"},
	{"/clientaccesspolicy.xml", "INFO", "Silverlight access policy"},
	{"/composer.json", "LOW", "PHP composer – reveals dependencies + versions"},
	{"/package.json", "LOW", "Node.js package – reveals dependencies + versions"},
	{"/Gemfile", "LOW", "Ruby Gemfile – reveals dependencies"},
	{"/requirements.txt", "LOW", "Python requirements – reveals dependencies"},
	{"/.well-known/matrix/server", "INFO", "Matrix server federation config"},
	{"/actuator", "HIGH", "Spring Boot Actuator – may expose health, env, metrics"},
	{"/actuator/env", "CRITICAL", "Spring Boot Actuator env – exposes all env vars"},
	{"/actuator/heapdump", "CRITICAL", "Spring Boot heap dump – memory contents"},
	{"/_cat/indices", "HIGH", "Elasticsearch index list"},
	{"/_nodes", "MEDIUM", "Elasticsearch cluster info"},
}

func (s *APIServer) handleFileScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "Use POST", nil)
		return
	}
	var req struct {
		URL         string `json:"url"`
		Concurrency int    `json:"concurrency"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.URL == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_URL", "Missing URL", "url is required", "", nil)
		return
	}

	baseURL := req.URL
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !isSafeTarget(baseURL) {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SSRF_BLOCKED", "Target Blocked", "Private/loopback hosts not permitted", "", nil)
		return
	}

	concurrency := req.Concurrency
	if concurrency <= 0 || concurrency > 50 {
		concurrency = 20
	}

	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var exposed []exposedFile
	var wg sync.WaitGroup

	for _, sp := range sensitivePaths {
		wg.Add(1)
		go func(path, severity, note string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := baseURL + path
			resp, err := client.Get(fullURL)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Only report 200 OK and interesting 403 (file exists but protected)
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
				return
			}

			ef := exposedFile{
				Path:       path,
				StatusCode: resp.StatusCode,
				Severity:   severity,
				Note:       note,
			}

			// For 200 responses, grab a preview
			if resp.StatusCode == http.StatusOK {
				preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				ef.SizeBytes = int(resp.ContentLength)
				previewStr := strings.TrimSpace(string(preview))
				// Redact obvious secrets in preview for safety
				if len(previewStr) > 200 {
					previewStr = previewStr[:200] + "…"
				}
				ef.Preview = previewStr
				if resp.StatusCode == http.StatusForbidden {
					ef.Note = note + " (exists but access forbidden)"
					ef.Severity = lowerSeverity(severity)
				}
			}

			mu.Lock()
			exposed = append(exposed, ef)
			mu.Unlock()
		}(sp.path, sp.severity, sp.note)
	}
	wg.Wait()

	// Sort by severity
	severityRank := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.Slice(exposed, func(i, j int) bool {
		return severityRank[exposed[i].Severity] < severityRank[exposed[j].Severity]
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":           req.URL,
		"probed":        len(sensitivePaths),
		"exposed_count": len(exposed),
		"exposed":       exposed,
		"scanned_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

func lowerSeverity(s string) string {
	switch s {
	case "CRITICAL":
		return "HIGH"
	case "HIGH":
		return "MEDIUM"
	case "MEDIUM":
		return "LOW"
	default:
		return "INFO"
	}
}
