package api

// ═══════════════════════════════════════════════════════════════════════════════
// HTTP MITM PROXY — API-controlled intercept engine
//
// Architecture:
//   POST /api/v1/mitm/start   — start HTTP proxy on given port
//   POST /api/v1/mitm/stop    — stop the proxy
//   GET  /api/v1/mitm/status  — current state + stats
//   GET  /api/v1/mitm/packets — paged list of intercepted sessions
//   POST /api/v1/mitm/clear   — wipe session store
//   POST /api/v1/mitm/inject  — inject custom headers for future requests
// ═══════════════════════════════════════════════════════════════════════════════

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mega-analyzer/pkg/internal/secrets"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION STORE
// ═══════════════════════════════════════════════════════════════════════════════

type MITMSession struct {
	ID          uint64            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	ClientAddr  string            `json:"client_addr"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Proto       string            `json:"proto"`
	ReqHeaders  map[string]string `json:"req_headers"`
	ReqBody     string            `json:"req_body,omitempty"`
	StatusCode  int               `json:"status_code"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody    string            `json:"resp_body,omitempty"`
	DurationMs  int64             `json:"duration_ms"`
	IsHTTPS     bool              `json:"is_https"`
	TLSVersion  string            `json:"tls_version,omitempty"`
	Injected    bool              `json:"injected,omitempty"`
	Alerts      []string          `json:"alerts,omitempty"`
}

type mitmStore struct {
	mu       sync.RWMutex
	sessions []*MITMSession
	counter  atomic.Uint64
	maxSize  int
}

func newMITMStore(max int) *mitmStore {
	if max <= 0 {
		max = 2000
	}
	return &mitmStore{maxSize: max}
}

func (st *mitmStore) Add(s *MITMSession) {
	s.ID = st.counter.Add(1)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions = append(st.sessions, s)
	if len(st.sessions) > st.maxSize {
		st.sessions = st.sessions[len(st.sessions)-st.maxSize:]
	}
}

func (st *mitmStore) List(offset, limit int) ([]*MITMSession, int) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	total := len(st.sessions)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	// Return newest first
	out := make([]*MITMSession, 0, end-offset)
	for i := total - 1 - offset; i >= 0 && len(out) < limit; i-- {
		out = append(out, st.sessions[i])
	}
	return out, total
}

func (st *mitmStore) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions = nil
}

func (st *mitmStore) Count() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.sessions)
}

// ═══════════════════════════════════════════════════════════════════════════════
// MITM PROXY STATE
// ═══════════════════════════════════════════════════════════════════════════════

type mitmState struct {
	mu            sync.Mutex
	running       bool
	listenAddr    string
	startedAt     time.Time
	listener      net.Listener
	store         *mitmStore
	injectHeaders map[string]string
	caCert        *x509.Certificate
	caKey         *rsa.PrivateKey
	certCache     map[string]*certCacheEntry
	certLRU       []string
	certCap       int
	certMu        sync.Mutex
	reqCount      atomic.Int64
	tlsCount      atomic.Int64
}

// certCacheEntry tracks a cached leaf certificate along with when it was
// created and when it stops being valid, so the cache can refuse to serve a
// cert past its own expiry instead of trusting count-based LRU alone.
type certCacheEntry struct {
	cert      *tls.Certificate
	createdAt time.Time
	expiresAt time.Time
}

var globalMITM = &mitmState{
	store:         newMITMStore(2000),
	injectHeaders: map[string]string{},
	certCache:     map[string]*certCacheEntry{},
	certCap:       400,
}

// certCacheJanitorOnce lazily starts the periodic certCache cleanup (every
// 30 min), so binaries importing pkg/api for non-MITM CLI use don't carry an
// unstoppable init()-time goroutine. The janitor lives as long as the
// process that actually serves MITM traffic.
var certCacheJanitorOnce sync.Once

func startCertCacheJanitor() {
	certCacheJanitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(30 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				evictCertLRU()
			}
		}()
	})
}

// ensureCA generates the ephemeral interception CA on first use instead of
// in init(): package init runs for every binary (including CLI runs that
// never touch MITM), paying ~100-300 ms of RSA generation and entropy per
// start, and the non-persistent key forced users to reinstall the CA after
// every restart. Called with globalMITM.mu held.
func ensureCA() error {
	if globalMITM.caCert != nil && globalMITM.caKey != nil {
		return nil
	}
	caKey, caCert, err := generateCA()
	if err != nil {
		return err
	}
	globalMITM.caKey = caKey
	globalMITM.caCert = caCert
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleMITMStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}
	var req struct {
		Port int `json:"port"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil || req.Port == 0 {
		req.Port = 8888
	}
	if req.Port < 1024 || req.Port > 65535 {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PORT", "Invalid Port", "port must be 1024-65535", "", nil)
		return
	}

	globalMITM.mu.Lock()
	defer globalMITM.mu.Unlock()

	if globalMITM.running {
		writeProblem(w, r, http.StatusConflict, "ERR_ALREADY_RUNNING", "Proxy Already Running",
			fmt.Sprintf("MITM proxy already active on %s", globalMITM.listenAddr), "Stop it first with POST /api/v1/mitm/stop", nil)
		return
	}

	if err := ensureCA(); err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_CA_GENERATION", "CA Generation Failed", err.Error(), "HTTPS interception will fall back to blind tunneling", nil)
	}

	bindHost := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_MITM_BIND"))
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", bindHost, req.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		writeProblem(w, r, http.StatusInternalServerError, "ERR_BIND_FAILED", "Cannot Bind Port", err.Error(), "", nil)
		return
	}

	globalMITM.running = true
	globalMITM.listenAddr = addr
	globalMITM.startedAt = time.Now()
	globalMITM.listener = ln
	globalMITM.store.Clear()
	globalMITM.reqCount.Store(0)
	globalMITM.tlsCount.Store(0)

	go func() {
		var retryDelay time.Duration
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					// Intentional shutdown via handleMITMStop; running is
					// already flipped to false there.
					return
				}
				// Back off on persistent errors instead of busy-spinning;
				// keep retrying so "running" continues to reflect that the
				// proxy is still trying to accept, rather than silently
				// dying while /mitm/status reports it as active.
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				time.Sleep(retryDelay)
				continue
			}
			retryDelay = 0
			go handleMITMConn(conn)
		}
	}()

	caPEM := ""
	if globalMITM.caCert != nil {
		caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: globalMITM.caCert.Raw}))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "started",
		"listen_addr": addr,
		"port":        req.Port,
		"ca_cert_pem": caPEM,
		"note":        "Configure your browser/device to use this as HTTP proxy. Import CA cert for HTTPS interception.",
	})
}

func (s *APIServer) handleMITMStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}

	globalMITM.mu.Lock()
	defer globalMITM.mu.Unlock()

	if !globalMITM.running {
		writeProblem(w, r, http.StatusConflict, "ERR_NOT_RUNNING", "Proxy Not Running", "No MITM proxy is currently active", "", nil)
		return
	}

	globalMITM.listener.Close()
	globalMITM.running = false

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "stopped",
		"sessions_saved": globalMITM.store.Count(),
		"uptime_seconds": int(time.Since(globalMITM.startedAt).Seconds()),
	})
}

func (s *APIServer) handleMITMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET", "", nil)
		return
	}

	globalMITM.mu.Lock()
	running := globalMITM.running
	addr := globalMITM.listenAddr
	started := globalMITM.startedAt
	globalMITM.mu.Unlock()

	uptime := 0
	if running {
		uptime = int(time.Since(started).Seconds())
	}

	caReady := globalMITM.caCert != nil
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"running":              running,
		"listen_addr":          addr,
		"uptime_seconds":       uptime,
		"sessions_captured":    globalMITM.store.Count(),
		"total_requests":       globalMITM.reqCount.Load(),
		"https_intercepted":    globalMITM.tlsCount.Load(),
		"ca_ready":             caReady,
		"inject_headers_count": len(copyInjectHeaders()),
	})
}

func (s *APIServer) handleMITMPackets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET", "", nil)
		return
	}

	offset := 0
	limit := 50
	q := r.URL.Query()
	fmt.Sscanf(q.Get("offset"), "%d", &offset)
	fmt.Sscanf(q.Get("limit"), "%d", &limit)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	sessions, total := globalMITM.store.List(offset, limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":    total,
		"offset":   offset,
		"limit":    limit,
		"sessions": sessions,
	})
}

func (s *APIServer) handleMITMClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}
	count := globalMITM.store.Count()
	globalMITM.store.Clear()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cleared": count,
	})
}

func (s *APIServer) handleMITMInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}
	var req struct {
		Headers map[string]string `json:"headers"`
		Clear   bool              `json:"clear"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}

	globalMITM.mu.Lock()
	if req.Clear {
		globalMITM.injectHeaders = map[string]string{}
	}
	for k, v := range req.Headers {
		globalMITM.injectHeaders[k] = v
	}
	headersCopy := make(map[string]string, len(globalMITM.injectHeaders))
	for k, v := range globalMITM.injectHeaders {
		headersCopy[k] = v
	}
	injected := len(headersCopy)
	globalMITM.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inject_headers_count": injected,
		"headers":              headersCopy,
	})
}

func (s *APIServer) handleMITMCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET", "", nil)
		return
	}
	globalMITM.mu.Lock()
	err := ensureCA()
	globalMITM.mu.Unlock()
	if err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "ERR_NO_CA", "CA Not Available", err.Error(), "Retry after fixing certificate generation", nil)
		return
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: globalMITM.caCert.Raw})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="mega-analyzer-mitm-ca.pem"`)
	w.WriteHeader(http.StatusOK)
	w.Write(caPEM)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROXY CONNECTION HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

func handleMITMConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	globalMITM.reqCount.Add(1)

	if req.Method == http.MethodConnect {
		if !mitmHostAllowed(req.Host) {
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
			return
		}
		// HTTPS MITM via CONNECT tunnel
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		handleHTTPSMITM(conn, req.Host)
		return
	}

	// Plain HTTP proxy
	handleHTTPMITM(conn, req)
}

// mitmForwardTransport is shared across all plain-HTTP MITM forwards so
// upstream connections are pooled instead of a fresh Transport (and its own
// connection pool) being allocated per request.
var mitmForwardTransport = &http.Transport{
	MaxIdleConns:        100,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

func handleHTTPMITM(conn net.Conn, req *http.Request) {
	start := time.Now()
	session := &MITMSession{
		Timestamp:  start,
		ClientAddr: conn.RemoteAddr().String(),
		Method:     req.Method,
		URL:        req.URL.String(),
		Host:       req.Host,
		Proto:      req.Proto,
		ReqHeaders: headersToMap(req.Header),
		IsHTTPS:    false,
	}

	// Read request body
	if req.Body != nil {
		bodyBytes, ok := readMITMBody(req.Body)
		req.Body.Close()
		if !ok {
			session.Alerts = append(session.Alerts, "Request body exceeds proxy buffer, session refused")
			globalMITM.store.Add(session)
			return
		}
		if len(bodyBytes) > 0 {
			session.ReqBody = truncateBody(bodyBytes)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}

	// Inject headers
	for k, v := range copyInjectHeaders() {
		req.Header.Set(k, v)
		session.Injected = true
	}

	// Forward request
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if !mitmHostAllowed(req.URL.Host) {
		session.Alerts = append(session.Alerts, "Blocked by MITM allowlist/offline policy")
		globalMITM.store.Add(session)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
		return
	}

	resp, err := mitmForwardTransport.RoundTrip(req)
	if err != nil {
		session.Alerts = append(session.Alerts, "Forward error: "+err.Error())
		globalMITM.store.Add(session)
		return
	}
	defer resp.Body.Close()

	session.StatusCode = resp.StatusCode
	session.RespHeaders = headersToMap(resp.Header)
	session.DurationMs = time.Since(start).Milliseconds()

	respBody, ok := readMITMBody(resp.Body)
	if !ok {
		session.Alerts = append(session.Alerts, "Response body exceeds proxy buffer, session refused")
		globalMITM.store.Add(session)
		return
	}
	if len(respBody) > 0 {
		session.RespBody = truncateBody(respBody)
	}

	// Analyze for interesting patterns
	session.Alerts = append(session.Alerts, analyzeSession(session)...)

	globalMITM.store.Add(session)

	// Send response back to client
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
	_ = resp.Write(conn)
}

func handleHTTPSMITM(conn net.Conn, hostPort string) {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	if !mitmHostAllowed(hostPort) {
		return
	}

	if globalMITM.caCert == nil || globalMITM.caKey == nil {
		// Fallback: blind tunnel (no inspection)
		upstream, err := net.DialTimeout("tcp", hostPort, 10*time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
		<-done
		_ = conn.SetDeadline(time.Now())
		_ = upstream.SetDeadline(time.Now())
		<-done
		return
	}

	// Get or generate leaf cert for this host
	cert, certErr := getOrGenerateCert(host)
	if certErr != nil {
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	globalMITM.tlsCount.Add(1)

	// host and the insecure-upstream flag are fixed for the life of this
	// connection, so build the upstream transport once and reuse it across
	// every keep-alive request instead of per request.
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: os.Getenv("MEGA_ANALYZER_MITM_INSECURE_UPSTREAM") == "1",
	}}
	defer transport.CloseIdleConnections()

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		start := time.Now()
		session := &MITMSession{
			Timestamp:  start,
			ClientAddr: conn.RemoteAddr().String(),
			Method:     req.Method,
			URL:        "https://" + host + req.URL.String(),
			Host:       host,
			Proto:      req.Proto,
			ReqHeaders: headersToMap(req.Header),
			IsHTTPS:    true,
			TLSVersion: tlsVersionName(tlsConn.ConnectionState().Version),
		}

		if req.Body != nil {
			bodyBytes, ok := readMITMBody(req.Body)
			req.Body.Close()
			if !ok {
				session.Alerts = append(session.Alerts, "Request body exceeds proxy buffer, session refused")
				globalMITM.store.Add(session)
				return
			}
			if len(bodyBytes) > 0 {
				session.ReqBody = truncateBody(bodyBytes)
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				req.ContentLength = int64(len(bodyBytes))
			}
		}

		// Inject custom headers
		for k, v := range copyInjectHeaders() {
			req.Header.Set(k, v)
			session.Injected = true
		}

		req.RequestURI = ""
		req.URL.Scheme = "https"
		req.URL.Host = host

		resp, err := transport.RoundTrip(req)
		if err != nil {
			session.Alerts = append(session.Alerts, "Forward error: "+err.Error())
			globalMITM.store.Add(session)
			return
		}

		session.StatusCode = resp.StatusCode
		session.RespHeaders = headersToMap(resp.Header)
		session.DurationMs = time.Since(start).Milliseconds()

		respBody, ok := readMITMBody(resp.Body)
		resp.Body.Close()
		if !ok {
			session.Alerts = append(session.Alerts, "Response body exceeds proxy buffer, session refused")
			globalMITM.store.Add(session)
			return
		}
		if len(respBody) > 0 {
			session.RespBody = truncateBody(respBody)
		}

		session.Alerts = append(session.Alerts, analyzeSession(session)...)
		globalMITM.reqCount.Add(1)
		globalMITM.store.Add(session)

		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.ContentLength = int64(len(respBody))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
		if err := resp.Write(tlsConn); err != nil {
			return
		}

		if !httpKeepAlive(req) {
			return
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CERTIFICATE GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

func generateCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"Mega-Analyzer MITM CA"},
			OrganizationalUnit: []string{"Security Research"},
			CommonName:         "Mega-Analyzer Intercept CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func getOrGenerateCert(host string) (*tls.Certificate, error) {
	certHost, ipSAN := mitmCertHost(host)
	if certHost == "" {
		return nil, fmt.Errorf("empty certificate host")
	}
	globalMITM.certMu.Lock()
	defer globalMITM.certMu.Unlock()

	if c, ok := globalMITM.certCache[certHost]; ok && time.Now().Before(c.expiresAt) {
		return c.cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	notAfter := now.Add(24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: certHost},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ipSAN != nil {
		tmpl.IPAddresses = []net.IP{ipSAN}
	} else {
		tmpl.DNSNames = []string{certHost, "*." + certHost}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, globalMITM.caCert, &key.PublicKey, globalMITM.caKey)
	if err != nil {
		return nil, err
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, globalMITM.caCert.Raw},
		PrivateKey:  key,
	}
	startCertCacheJanitor()
	// LRU eviction: cap at certCap entries. Re-generating an expired entry
	// does not grow the cache (its key is already present), so only check
	// the cap when this host is genuinely new.
	if _, exists := globalMITM.certCache[certHost]; !exists {
		if len(globalMITM.certCache) >= globalMITM.certCap && len(globalMITM.certLRU) > 0 {
			oldest := globalMITM.certLRU[0]
			globalMITM.certLRU = globalMITM.certLRU[1:]
			delete(globalMITM.certCache, oldest)
		}
		globalMITM.certLRU = append(globalMITM.certLRU, certHost)
	}
	globalMITM.certCache[certHost] = &certCacheEntry{cert: tlsCert, createdAt: now, expiresAt: notAfter}
	return tlsCert, nil
}

// evictCertLRU is called periodically to purge entries older than 1 hour,
// keeping the cache small between cert regenerations rather than only
// bounding it by count.
func evictCertLRU() {
	globalMITM.certMu.Lock()
	defer globalMITM.certMu.Unlock()
	cutoff := time.Now().Add(-1 * time.Hour)
	kept := globalMITM.certLRU[:0]
	for _, host := range globalMITM.certLRU {
		entry, ok := globalMITM.certCache[host]
		if !ok {
			continue
		}
		if entry.createdAt.Before(cutoff) {
			delete(globalMITM.certCache, host)
			continue
		}
		kept = append(kept, host)
	}
	globalMITM.certLRU = kept
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func copyInjectHeaders() map[string]string {
	globalMITM.mu.Lock()
	defer globalMITM.mu.Unlock()
	out := make(map[string]string, len(globalMITM.injectHeaders))
	for k, v := range globalMITM.injectHeaders {
		out[k] = v
	}
	return out
}

func mitmCertHost(hostport string) (string, net.IP) {
	h := strings.TrimSpace(hostport)
	if splitHost, _, err := net.SplitHostPort(h); err == nil {
		h = splitHost
	}
	h = strings.Trim(strings.TrimSuffix(h, "."), "[]")
	if ip := net.ParseIP(h); ip != nil {
		return h, ip
	}
	return strings.ToLower(h), nil
}

func mitmHostAllowed(hostport string) bool {
	host, ip := mitmCertHost(hostport)
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	allowedCSV := os.Getenv("MEGA_ANALYZER_MITM_ALLOWED_DOMAINS")
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
		for _, allowed := range strings.Split(allowedCSV, ",") {
			if aip := net.ParseIP(strings.TrimSpace(allowed)); aip != nil && aip.Equal(ip) {
				return true
			}
		}
		return false
	}
	if strings.TrimSpace(allowedCSV) == "" {
		// Offline-by-default: explicit allowlist required for non-local hosts.
		return false
	}
	for _, allowed := range strings.Split(allowedCSV, ",") {
		allowed = strings.Trim(strings.ToLower(strings.TrimSpace(allowed)), ".")
		if allowed == "" {
			continue
		}
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, "; ")
	}
	return m
}

func truncateBody(b []byte) string {
	if len(b) > 4096 {
		return string(b[:4096]) + fmt.Sprintf("\n... [truncated %d bytes]", len(b)-4096)
	}
	return string(b)
}

// maxMITMBodyBytes caps a single proxied request/response body held in
// memory. Only a 4KB preview is ever stored; anything larger is refused
// rather than buffered, so a malicious peer cannot OOM the proxy by sending
// gigabytes after the preview was taken.
func maxMITMBodyBytes() int64 {
	const def = 32 << 20
	raw := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_MITM_MAX_BODY_BYTES"))
	if raw == "" {
		return def
	}
	var n int64
	if _, err := fmt.Sscanf(raw, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

// readMITMBody reads at most limit+1 bytes. ok=false means the body exceeds
// what the proxy will buffer (or a read failed); the caller must refuse the
// session and close the connection, never forward a prefix as the whole body.
func readMITMBody(r io.Reader) (body []byte, ok bool) {
	limit := maxMITMBodyBytes()
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, false
	}
	return body, true
}

func httpKeepAlive(req *http.Request) bool {
	return req.Proto == "HTTP/1.1" && strings.ToLower(req.Header.Get("Connection")) != "close"
}

var _ = httputil.NewSingleHostReverseProxy // keep import used

func analyzeSession(s *MITMSession) []string {
	var alerts []string

	// Check for credentials in URL
	if strings.Contains(s.URL, "password=") || strings.Contains(s.URL, "passwd=") || strings.Contains(s.URL, "pass=") {
		alerts = append(alerts, "⚠ Credentials detected in URL query string")
	}
	// Check for JWT in headers
	if auth := s.ReqHeaders["Authorization"]; strings.HasPrefix(auth, "Bearer ey") {
		alerts = append(alerts, "🔑 JWT Bearer token captured in Authorization header")
	}
	// Check for API keys
	for k, v := range s.ReqHeaders {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "api-key") || strings.Contains(kl, "x-api-key") || strings.Contains(kl, "apikey") {
			alerts = append(alerts, fmt.Sprintf("🔑 API key detected in header: %s = %s", k, maskValue(v)))
		}
	}
	providerText := s.URL + "\n" + s.ReqBody + "\n" + s.RespBody
	for k, v := range s.ReqHeaders {
		providerText += "\n" + k + ": " + v
	}
	for k, v := range s.RespHeaders {
		providerText += "\n" + k + ": " + v
	}
	seenProviders := map[string]struct{}{}
	for _, sf := range secrets.DetectProviders(providerText, s.Host) {
		key := sf.RuleID + sf.MaskedValue
		if _, ok := seenProviders[key]; ok {
			continue
		}
		seenProviders[key] = struct{}{}
		alerts = append(alerts, fmt.Sprintf("🔑 Provider credential detected (%s): %s", sf.Provider, sf.MaskedValue))
	}

	// Check response for sensitive data
	if s.RespBody != "" {
		if strings.Contains(s.RespBody, "\"password\"") || strings.Contains(s.RespBody, "\"secret\"") {
			alerts = append(alerts, "⚠ Possible sensitive fields in response body")
		}
		if strings.Contains(s.RespBody, "-----BEGIN RSA PRIVATE KEY-----") || strings.Contains(s.RespBody, "-----BEGIN PRIVATE KEY-----") {
			alerts = append(alerts, "🔴 CRITICAL: Private key found in response!")
		}
	}
	// Missing HTTPS
	if !s.IsHTTPS && (strings.Contains(s.URL, "login") || strings.Contains(s.URL, "auth")) {
		alerts = append(alerts, "⚠ Authentication endpoint accessed over plain HTTP")
	}
	// Check for CORS issues in response
	if acao := s.RespHeaders["Access-Control-Allow-Origin"]; acao == "*" {
		alerts = append(alerts, "ℹ Wildcard CORS header in response")
	}
	return alerts
}

func maskValue(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "****" + v[len(v)-4:]
}
