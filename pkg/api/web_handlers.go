package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CORS MISCONFIGURATION CHECKER
// ═══════════════════════════════════════════════════════════════════════════════

type CORSFinding struct {
	Test        string `json:"test"`
	Origin      string `json:"origin_sent"`
	ACAO        string `json:"access_control_allow_origin"`
	ACAC        string `json:"access_control_allow_credentials"`
	Vulnerable  bool   `json:"vulnerable"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

func (s *APIServer) handleCORSCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
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
	if !isSafeTarget(req.URL) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "Target URL points to an internal or local IP.", "Use a public URL.", nil)
		return
	}

	client, err := safeHTTPClient(8*time.Second, req.URL)
	if err != nil {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", err.Error(), "Use a public URL.", nil)
		return
	}

	host := extractHost(req.URL)
	testOrigins := []struct {
		name   string
		origin string
	}{
		{"Arbitrary Origin", "https://evil.attacker.com"},
		{"Null Origin", "null"},
		{"Subdomain of Target", "https://evil." + host},
		{"Pre-domain Match", "https://evil-" + host},
		{"Post-domain Match", "https://" + host + ".evil.com"},
		{"HTTP Downgrade", "http://" + host},
	}

	var findings []CORSFinding
	var vulnerable bool

	for _, t := range testOrigins {
		httpReq, err := http.NewRequest("GET", req.URL, nil)
		if err != nil {
			continue
		}
		httpReq.Header.Set("Origin", t.origin)
		httpReq.Header.Set("User-Agent", "Mozilla/5.0 CORS-Checker/Mega-Analyzer")

		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		finding := CORSFinding{
			Test:   t.name,
			Origin: t.origin,
			ACAO:   acao,
			ACAC:   acac,
		}

		if acao == "*" && acac == "true" {
			finding.Vulnerable = true
			finding.Severity = "CRITICAL"
			finding.Description = "Wildcard origin (*) combined with credentials=true — attackers can make credentialed cross-origin requests from any domain"
			vulnerable = true
		} else if acao == t.origin && acac == "true" {
			finding.Vulnerable = true
			finding.Severity = "HIGH"
			finding.Description = fmt.Sprintf("Server reflects attacker-controlled origin '%s' with credentials — full CORS exploit possible", t.origin)
			vulnerable = true
		} else if acao == t.origin {
			finding.Vulnerable = true
			finding.Severity = "MEDIUM"
			finding.Description = fmt.Sprintf("Server reflects attacker origin '%s' (without credentials flag)", t.origin)
			vulnerable = true
		} else if acao == "*" {
			finding.Severity = "LOW"
			finding.Description = "Wildcard CORS allowed (no credentials, acceptable for public APIs)"
		}

		findings = append(findings, finding)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":        req.URL,
		"vulnerable": vulnerable,
		"findings":   findings,
		"summary":    corsRiskSummary(findings),
	})
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	parts := strings.SplitN(rawURL, "/", 2)
	return parts[0]
}

func corsRiskSummary(findings []CORSFinding) string {
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			return "CRITICAL: Full CORS bypass with credential leakage possible"
		}
	}
	for _, f := range findings {
		if f.Severity == "HIGH" {
			return "HIGH: Origin reflection with credentials — cross-origin data theft possible"
		}
	}
	for _, f := range findings {
		if f.Severity == "MEDIUM" {
			return "MEDIUM: Origin reflection without credentials"
		}
	}
	return "PASS: No exploitable CORS misconfiguration detected"
}

// ═══════════════════════════════════════════════════════════════════════════════
// JWT ANALYZER & CRACKER
// ═══════════════════════════════════════════════════════════════════════════════

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacSHA384(key, data []byte) []byte {
	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacSHA512(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func (s *APIServer) handleJWTAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}
	var req struct {
		Token        string   `json:"token"`
		WeakKeys     []string `json:"weak_keys,omitempty"`
		CheckAlgNone bool     `json:"check_alg_none"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Token == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_TOKEN", "Missing Token", "token is required", "", nil)
		return
	}

	token := strings.TrimSpace(req.Token)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_JWT", "Invalid JWT", "JWT must have exactly 3 dot-separated parts", "", nil)
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_JWT", "Invalid JWT Header", err.Error(), "", nil)
		return
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_JWT", "Invalid JWT Header JSON", err.Error(), "", nil)
		return
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_JWT", "Invalid JWT Payload", err.Error(), "", nil)
		return
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_JWT", "Invalid JWT Payload JSON", err.Error(), "", nil)
		return
	}

	var issues []map[string]string
	alg, _ := header["alg"].(string)

	if strings.EqualFold(alg, "none") {
		issues = append(issues, map[string]string{
			"severity":    "CRITICAL",
			"title":       "Algorithm None Attack",
			"description": "JWT uses alg=none — signature is not verified. Attackers can forge arbitrary tokens.",
		})
	}

	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "EC") || strings.HasPrefix(alg, "PS") {
		issues = append(issues, map[string]string{
			"severity":    "HIGH",
			"title":       "Algorithm Confusion Attack Vector",
			"description": fmt.Sprintf("Asymmetric algorithm %s — verify server rejects HS256 with public key as HMAC secret (CVE-2015-9235)", alg),
		})
	}

	if exp, ok := payload["exp"]; ok {
		var expFloat float64
		switch v := exp.(type) {
		case float64:
			expFloat = v
		}
		expTime := time.Unix(int64(expFloat), 0)
		if time.Now().After(expTime) {
			issues = append(issues, map[string]string{
				"severity":    "MEDIUM",
				"title":       "Token Expired",
				"description": fmt.Sprintf("Token expired at %s — check if server validates exp claim", expTime.UTC().Format(time.RFC3339)),
			})
		}
	} else {
		issues = append(issues, map[string]string{
			"severity":    "MEDIUM",
			"title":       "No Expiration Claim",
			"description": "Token has no 'exp' claim — tokens live indefinitely unless explicitly revoked",
		})
	}

	sensitiveKeys := []string{"password", "passwd", "secret", "key", "credit_card", "ssn", "private"}
	for k := range payload {
		for _, sk := range sensitiveKeys {
			if strings.Contains(strings.ToLower(k), sk) {
				issues = append(issues, map[string]string{
					"severity":    "HIGH",
					"title":       "Sensitive Data in Payload",
					"description": fmt.Sprintf("Claim '%s' may contain sensitive data — JWT payload is base64 only, NOT encrypted", k),
				})
			}
		}
	}

	// Weak secret brute force for HMAC algorithms
	var crackedSecret string
	defaultWeakKeys := []string{
		"secret", "password", "123456", "test", "jwt", "key", "token", "admin",
		"letmein", "qwerty", "abc123", "changeme", "supersecret", "yourjwtsecret",
		"jwt_secret", "jwtSecret", "secret123", "mykey", "access_token_secret",
		"", "null", "undefined", "dev", "development", "prod", "production",
		"HS256", "HS384", "HS512", "jwt-secret", "api-key", "api_key",
	}
	allKeys := append(defaultWeakKeys, req.WeakKeys...)

	if strings.HasPrefix(alg, "HS") {
		signingInput := parts[0] + "." + parts[1]
		providedSig, _ := base64.RawURLEncoding.DecodeString(parts[2])

		var hashFunc func(key, data []byte) []byte
		switch alg {
		case "HS256":
			hashFunc = hmacSHA256
		case "HS384":
			hashFunc = hmacSHA384
		case "HS512":
			hashFunc = hmacSHA512
		}

		if hashFunc != nil {
			for _, k := range allKeys {
				computed := hashFunc([]byte(k), []byte(signingInput))
				if hmacEqual(computed, providedSig) {
					crackedSecret = k
					issues = append(issues, map[string]string{
						"severity":    "CRITICAL",
						"title":       "Weak Secret Key Cracked",
						"description": fmt.Sprintf("JWT signed with weak secret: '%s' — attacker can forge any token", k),
					})
					break
				}
			}
		}
	}

	noneToken := ""
	if req.CheckAlgNone {
		noneHeader := map[string]interface{}{"alg": "none", "typ": "JWT"}
		nhBytes, _ := json.Marshal(noneHeader)
		noneToken = base64.RawURLEncoding.EncodeToString(nhBytes) + "." + parts[1] + "."
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"header":            header,
		"payload":           payload,
		"algorithm":         alg,
		"issues":            issues,
		"cracked_secret":    crackedSecret,
		"none_bypass_token": noneToken,
		"raw_parts": map[string]string{
			"header":    string(headerBytes),
			"payload":   string(payloadBytes),
			"signature": parts[2],
		},
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPEN REDIRECT CHECKER
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleOpenRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
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

	if !isSafeTarget(req.URL) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "Target URL points to an internal or local IP.", "Use a public URL.", nil)
		return
	}

	redirectPayloads := []string{
		"https://evil.com", "//evil.com", "///evil.com",
		"https://evil.com%09", "https://evil.com%0a",
		"\\\\evil.com", "//evil.com/%2F..",
	}
	params := []string{
		"url", "redirect", "redirect_url", "return", "return_url",
		"returnTo", "next", "goto", "target", "destination", "dest", "redir",
		"forward", "callback", "continue", "r", "u", "link", "ref", "to",
	}

	client, err := safeHTTPClient(6*time.Second, req.URL)
	if err != nil {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", err.Error(), "Use a public URL.", nil)
		return
	}

	type RedirectResult struct {
		Param      string `json:"param"`
		Payload    string `json:"payload"`
		StatusCode int    `json:"status_code"`
		Location   string `json:"location"`
		Vulnerable bool   `json:"vulnerable"`
	}

	var results []RedirectResult
	var found bool

	for _, param := range params {
		if found {
			break
		}
		for _, payload := range redirectPayloads {
			testURL := req.URL
			if strings.Contains(testURL, "?") {
				testURL += "&" + param + "=" + payload
			} else {
				testURL += "?" + param + "=" + payload
			}
			httpReq, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(httpReq)
			if err != nil {
				continue
			}
			resp.Body.Close()

			loc := resp.Header.Get("Location")
			vuln := (resp.StatusCode >= 301 && resp.StatusCode <= 307) &&
				(strings.Contains(loc, "evil.com") || strings.HasPrefix(loc, "//evil"))

			if vuln {
				results = append(results, RedirectResult{
					Param: param, Payload: payload,
					StatusCode: resp.StatusCode, Location: loc, Vulnerable: true,
				})
				found = true
				break
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":           req.URL,
		"vulnerable":    found,
		"findings":      results,
		"params_tested": len(params),
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECTORY / PATH BRUTEFORCE
// ═══════════════════════════════════════════════════════════════════════════════

var dirWordlist = []string{
	"admin", "administrator", "login", "dashboard", "panel", "api", "api/v1", "api/v2",
	"backup", "backups", ".git", ".env", ".htaccess", ".htpasswd", "config",
	"wp-admin", "wp-config.php", "wp-login.php", "phpmyadmin", "pma",
	"test", "dev", "debug", "console", "shell", "cmd",
	"upload", "uploads", "files", "static", "assets", "media", "images",
	"docs", "documentation", "swagger", "openapi", "graphql",
	"robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
	"actuator", "actuator/health", "actuator/env", "actuator/metrics",
	"metrics", "health", "healthz", "status", "server-status", "info", "phpinfo.php",
	"trace.axd", "elmah.axd", "error.log", "access.log",
	"id_rsa", "id_dsa", "private.key", "server.key", "cert.pem",
	"web.config", "appsettings.json", "application.properties",
	"docker-compose.yml", "Dockerfile", "package.json", "composer.json",
	"requirements.txt", ".dockerignore", ".gitignore",
	"v1", "v2", "v3", "internal", "private", "secret", "hidden",
	"reset", "forgot", "password", "register", "signup", "logout",
	"user", "users", "account", "accounts", "profile",
	"search", "manage", "management", "settings",
	"cron", "jobs", "tasks", "queue", "worker",
	"install", "setup", "update", "upgrade", "migrate",
	"debug.php", "test.php", "temp.php", "old.php",
	"_debug", "_profiler", "__debug__", "telescope", "horizon",
}

type DirScanResult struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"content_length"`
	Redirect   string `json:"redirect,omitempty"`
	Notable    bool   `json:"notable"`
	Note       string `json:"note,omitempty"`
}

func (s *APIServer) handleDirScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}
	var req struct {
		URL         string   `json:"url"`
		WordList    []string `json:"wordlist,omitempty"`
		Concurrency int      `json:"concurrency"`
		Extensions  []string `json:"extensions,omitempty"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.URL == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_URL", "Missing URL", "url is required", "", nil)
		return
	}
	if !isSafeTarget(req.URL) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "Target URL points to an internal or local IP.", "Use a public URL.", nil)
		return
	}
	if req.Concurrency <= 0 || req.Concurrency > 50 {
		req.Concurrency = 20
	}

	wordlist := req.WordList
	if len(wordlist) == 0 {
		wordlist = dirWordlist
	}
	exts := req.Extensions
	if len(exts) == 0 {
		exts = []string{"", ".php", ".html", ".bak", ".old", ".txt"}
	}

	var paths []string
	for _, word := range wordlist {
		if strings.Contains(word, ".") {
			paths = append(paths, word)
		} else {
			for _, ext := range exts {
				paths = append(paths, word+ext)
			}
		}
	}

	baseURL := strings.TrimRight(req.URL, "/")
	client, err := safeHTTPClient(6*time.Second, req.URL)
	if err != nil {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", err.Error(), "Use a public URL.", nil)
		return
	}

	sem := make(chan struct{}, req.Concurrency)
	var mu sync.Mutex
	var results []DirScanResult
	var wg sync.WaitGroup

	sensitivePatterns := []string{
		".git", ".env", "config", "backup", "admin", "actuator",
		"debug", "phpinfo", "secret", "private", "id_rsa", ".htpasswd",
		"web.config", "appsettings", "docker-compose", "requirements",
	}

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := baseURL + "/" + p
			httpReq, err := http.NewRequest("GET", fullURL, nil)
			if err != nil {
				return
			}
			httpReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Mega-Analyzer-DirScan/1.0)")

			resp, err := client.Do(httpReq)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

			if resp.StatusCode == 404 || resp.StatusCode == 400 {
				return
			}

			notable := resp.StatusCode == 200 || resp.StatusCode == 204
			note := ""
			for _, sp := range sensitivePatterns {
				if strings.Contains(p, sp) {
					notable = true
					note = "⚠ Sensitive path exposed"
					break
				}
			}

			res := DirScanResult{
				Path:       "/" + p,
				StatusCode: resp.StatusCode,
				Size:       resp.ContentLength,
				Redirect:   resp.Header.Get("Location"),
				Notable:    notable,
				Note:       note,
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(path)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":          baseURL,
		"paths_tested": len(paths),
		"found":        len(results),
		"results":      results,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// TECH STACK DETECTOR (WhatWeb-style, engine in tech_fingerprint.go)
// ═══════════════════════════════════════════════════════════════════════════════

// redirectHop is one step of the redirect chain leading to the final page.
type redirectHop struct {
	Status int    `json:"status"`
	URL    string `json:"url"`
}

// fetchFinalPage GETs startURL and follows up to 4 redirects manually. Each
// hop is re-validated through safeHTTPClient (scheme, private-IP and DNS
// rebinding checks) and pinned to a freshly resolved IP, so a redirect can
// never pivot the request onto an internal address. Returns the final
// response, its body (capped), the final URL and the hop chain.
func fetchFinalPage(startURL string) (*http.Response, string, []redirectHop, error) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
	var hops []redirectHop
	current := startURL

	for i := 0; i <= 4; i++ {
		client, err := safeHTTPClient(10*time.Second, current)
		if err != nil {
			return nil, "", hops, err
		}
		httpReq, err := http.NewRequest("GET", current, nil)
		if err != nil {
			return nil, "", hops, err
		}
		httpReq.Header.Set("User-Agent", ua)
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, "", hops, err
		}

		if resp.StatusCode >= 301 && resp.StatusCode <= 308 {
			loc := resp.Header.Get("Location")
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if loc == "" {
				return nil, "", hops, fmt.Errorf("redirect without Location header")
			}
			next, err := url.Parse(loc)
			if err != nil {
				return nil, "", hops, fmt.Errorf("bad Location %q: %w", loc, err)
			}
			base, _ := url.Parse(current)
			next = base.ResolveReference(next)
			hops = append(hops, redirectHop{Status: resp.StatusCode, URL: next.String()})
			current = next.String()
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		return resp, string(bodyBytes), hops, nil
	}
	return nil, "", hops, fmt.Errorf("too many redirects")
}

func (s *APIServer) handleTechDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
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
	if !isSafeTarget(req.URL) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "Target URL points to an internal or local IP.", "Use a public URL.", nil)
		return
	}
	resp, body, hops, err := fetchFinalPage(req.URL)
	if err != nil {
		status := http.StatusBadGateway
		code := "ERR_UNREACHABLE"
		if strings.Contains(err.Error(), "private IP") || strings.Contains(err.Error(), "blocked host") {
			status = http.StatusForbidden
			code = "ERR_SSRF"
		}
		writeProblem(w, r, status, code, "Target Unreachable", err.Error(), "Use a public URL.", nil)
		return
	}

	detected := fingerprintSite(resp.Header, resp.Cookies(), body)

	hdrs := map[string]string{}
	for k, v := range resp.Header {
		hdrs[k] = strings.Join(v, "; ")
	}

	result := map[string]interface{}{
		"url":      req.URL,
		"status":   resp.StatusCode,
		"title":    extractPageTitle(body),
		"summary":  techSummary(detected),
		"detected": detected,
		"count":    len(detected),
		"headers":  hdrs,
	}
	if len(hops) > 0 {
		result["final_url"] = hops[len(hops)-1].URL
		result["redirects"] = hops
	}
	writeJSON(w, http.StatusOK, result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// COOKIE SECURITY ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

type CookieIssue struct {
	Cookie      string `json:"cookie"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

func (s *APIServer) handleCookieAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
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

	if !isSafeTarget(req.URL) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "Target URL points to an internal or local IP.", "Use a public URL.", nil)
		return
	}

	client, err := safeHTTPClient(8*time.Second, req.URL)
	if err != nil {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", err.Error(), "Use a public URL.", nil)
		return
	}
	resp, err := client.Get(req.URL)
	if err != nil {
		writeProblem(w, r, http.StatusBadGateway, "ERR_UNREACHABLE", "Target Unreachable", err.Error(), "", nil)
		return
	}
	resp.Body.Close()

	var issues []CookieIssue
	var cookieSummary []map[string]interface{}
	isHTTPS := strings.HasPrefix(req.URL, "https://")

	for _, c := range resp.Cookies() {
		summary := map[string]interface{}{
			"name":     c.Name,
			"value":    maskCookieValue(c.Value),
			"secure":   c.Secure,
			"httponly": c.HttpOnly,
			"samesite": sameSiteName(c.SameSite),
			"path":     c.Path,
			"domain":   c.Domain,
		}
		cookieSummary = append(cookieSummary, summary)

		if !c.Secure && isHTTPS {
			issues = append(issues, CookieIssue{
				Cookie: c.Name, Issue: "Missing Secure Flag", Severity: "HIGH",
				Description: fmt.Sprintf("Cookie '%s' lacks Secure flag — can be sent over HTTP in mixed-content scenarios", c.Name),
			})
		}
		if !c.HttpOnly {
			sev := "MEDIUM"
			if isSessionCookieName(c.Name) {
				sev = "HIGH"
			}
			issues = append(issues, CookieIssue{
				Cookie: c.Name, Issue: "Missing HttpOnly Flag", Severity: sev,
				Description: fmt.Sprintf("Cookie '%s' lacks HttpOnly — JavaScript can access it (XSS steals session)", c.Name),
			})
		}
		if c.SameSite == http.SameSiteDefaultMode {
			issues = append(issues, CookieIssue{
				Cookie: c.Name, Issue: "Missing SameSite Attribute", Severity: "MEDIUM",
				Description: fmt.Sprintf("Cookie '%s' has no SameSite attribute — CSRF attacks may succeed", c.Name),
			})
		}
		if isSessionCookieName(c.Name) && (!c.Secure || !c.HttpOnly) {
			issues = append(issues, CookieIssue{
				Cookie: c.Name, Issue: "Session Cookie Poorly Configured", Severity: "CRITICAL",
				Description: fmt.Sprintf("Session/auth cookie '%s' is missing critical security flags", c.Name),
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":     req.URL,
		"cookies": cookieSummary,
		"issues":  issues,
		"count":   len(resp.Cookies()),
	})
}

func maskCookieValue(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}

func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Not set"
	}
}

func isSessionCookieName(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range []string{"session", "sess", "auth", "token", "jwt", "access", "refresh", "sid", "uid"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBDOMAIN ENUMERATOR (standalone via API)
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleSubdomainEnum(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST", "", nil)
		return
	}
	var req struct {
		Domain      string   `json:"domain"`
		WordList    []string `json:"wordlist,omitempty"`
		Concurrency int      `json:"concurrency"`
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON", err.Error(), "", nil)
		return
	}
	if req.Domain == "" {
		writeProblem(w, r, http.StatusBadRequest, "ERR_MISSING_DOMAIN", "Missing Domain", "domain is required", "", nil)
		return
	}
	// Cheap request-shape validation must run BEFORE isSafeTarget, which does
	// a blocking DNS resolution. Otherwise an oversized wordlist pays the full
	// SSRF/DNS latency (and returns 403 on resolve failure) instead of a fast,
	// deterministic 400.
	if len(req.WordList) > 10000 {
		writeProblem(w, r, http.StatusBadRequest, "ERR_WORDLIST_TOO_LARGE", "Wordlist Too Large", "Maximum 10000 entries per wordlist", "Reduce wordlist size", nil)
		return
	}
	if !isSafeTarget("http://" + req.Domain) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "Domain resolves to an internal or local IP.", "Use a public domain or lab resolver.", nil)
		return
	}
	if req.Concurrency <= 0 || req.Concurrency > 200 {
		req.Concurrency = 100
	}

	wordlist := req.WordList
	if len(wordlist) == 0 {
		wordlist = subdomainWordlist
	}

	sem := make(chan struct{}, req.Concurrency)
	var mu sync.Mutex
	var found []map[string]interface{}
	var wg sync.WaitGroup

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
				found = append(found, map[string]interface{}{
					"subdomain": fqdn,
					"ips":       addrs,
				})
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain":     req.Domain,
		"tested":     len(wordlist),
		"found":      len(found),
		"subdomains": found,
	})
}
